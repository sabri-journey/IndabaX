"""Minimal OpenAI-compatible chat-completions server for Qwen3-8B, so
AgentDojo's LocalLLM pipeline element (which expects an OpenAI-compatible
API on port 8000) can drive it as a live agent.

Model loading is copied verbatim from the Sentinel Starter Kit's own proven
src/sentinel/models/hf_adapter.py (SENTINEL_4BIT=1 path, already verified
working on this exact 8GB card) -- reused, not reinvented, so this doesn't
re-solve the 4-bit-on-8GB puzzle a second time. This file lives outside
both the IndabaX repo and the Sentinel Starter Kit; it touches neither.

Deliberately does NOT inject SENTINEL's own SYSTEM_PROMPT or JSON action
format -- AgentDojo's own LocalLLM pipeline element already builds its own
system prompt (the <function=name>{...}</function> tool-calling convention)
before these messages ever reach this server. This server is a dumb
model-serving shim: same model (Qwen3-8B, SENTINEL's own reference agent),
same "no extra instructions added" principle hf_adapter.py's own docstring
states, just a different caller.
"""

from __future__ import annotations

import os
import time
import uuid

import torch
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoModelForCausalLM, AutoTokenizer, BitsAndBytesConfig

MODEL_PATH = "Qwen/Qwen3-8B"
MAX_NEW_TOKENS = 768

app = FastAPI()
tokenizer = None
model = None


class ChatMessage(BaseModel):
    role: str
    content: str


class ChatCompletionRequest(BaseModel):
    model: str
    messages: list[ChatMessage]
    temperature: float | None = 0.0
    top_p: float | None = 0.9
    seed: int | None = None


@app.on_event("startup")
def load_model():
    global tokenizer, model
    print("[qwen_openai_server] loading tokenizer + model (4-bit NF4)...", flush=True)
    tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH, local_files_only=True)
    bnb = BitsAndBytesConfig(
        load_in_4bit=True,
        bnb_4bit_quant_type="nf4",
        bnb_4bit_compute_dtype=torch.float16,
        bnb_4bit_use_double_quant=True,
    )
    model = AutoModelForCausalLM.from_pretrained(
        MODEL_PATH,
        local_files_only=True,
        quantization_config=bnb,
        dtype=torch.float16,
        device_map={"": 0},
    )
    print("[qwen_openai_server] model loaded.", flush=True)


@app.post("/v1/chat/completions")
def chat_completions(req: ChatCompletionRequest):
    messages = [{"role": m.role, "content": m.content} for m in req.messages]
    prompt = tokenizer.apply_chat_template(
        messages,
        tokenize=False,
        add_generation_prompt=True,
        enable_thinking=False,
    )
    inputs = tokenizer([prompt], return_tensors="pt").to(model.device)

    do_sample = bool(req.temperature and req.temperature > 0.0)
    gen_kwargs = {"max_new_tokens": MAX_NEW_TOKENS, "do_sample": do_sample}
    if do_sample:
        gen_kwargs["temperature"] = req.temperature
        gen_kwargs["top_p"] = req.top_p

    output = model.generate(**inputs, **gen_kwargs)
    text = tokenizer.decode(output[0][inputs["input_ids"].shape[-1]:], skip_special_tokens=True)

    return {
        "id": f"chatcmpl-{uuid.uuid4().hex[:24]}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": req.model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": text},
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": int(inputs["input_ids"].shape[-1]),
            "completion_tokens": int(output.shape[-1] - inputs["input_ids"].shape[-1]),
            "total_tokens": int(output.shape[-1]),
        },
    }


@app.get("/healthz")
def healthz():
    return {"status": "ok", "model_loaded": model is not None}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
