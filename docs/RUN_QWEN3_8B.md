# Running the real Qwen3-8B reference agent (build step 10)

## Bootstrap prompt for a fresh Claude Code session on this machine

Paste this after cloning both repos (step 1 below) and opening Claude Code
in `~/IndabaX`:

> We're competing in SENTINEL (IndabaX Tunisia 2026), deadline 22/09 23:59.
> The defense itself is fully built and committed in this repo — read
> `README.md` (results/architecture overview), `FIXLOG.md` (full build
> history with every bug found and fixed), and `SAFETY.md` first to get
> oriented. It's been validated clean against the mock model
> (`results/RESULTS_SUMMARY.md`); the one remaining step is build step 10:
> validate against the real Qwen3-8B reference agent on this machine's 8GB
> GPU, which is what you're here to do. Follow `docs/RUN_QWEN3_8B.md`
> exactly — it has the setup, a pre-diagnosed and already-fixed
> quantization patch (`docs/patches/hf_adapter_4bit.patch`, root-caused on
> a 6GB card, needs re-verifying on this 8GB one), the eval commands, and
> which scenarios to capture traces for. Do not modify anything under
> `src/defense/` — that's the finished, tested defense; this task is purely
> about running the reference agent against it and reporting results
> honestly, including if qwen3-8b behaves differently than mock did. Report
> back what you find at each step rather than running silently to the end.


Everything so far has been validated against `--model mock` only. This is
the guide to re-validate against the actual Qwen3-8B reference agent and
capture the traces the demo video is built around — written for a Windows
machine with an 8GB GPU (RTX 5060), run through **WSL2**, not native Windows
Python (bitsandbytes/CUDA is meaningfully less reliable on native Windows).

## Why WSL2, and why 8GB is enough here

We already tried this on a 6GB card and hit a hard capacity ceiling: Qwen3-8B
at 4-bit needs ~5.55GB (mostly weights; bitsandbytes keeps the embedding/
lm_head layers unquantized, which is real overhead), and every CPU-offload
fallback we tried hit its own memory-management issues in `accelerate`. An
8GB card has ~7.4GB usable — comfortable margin for the same 4-bit config
with **no offload needed at all**, which sidesteps that whole class of
problems. See `FIXLOG.md`-adjacent notes below for exactly what was broken
and fixed.

## 0. Prerequisites

- WSL2 with Ubuntu, and the **NVIDIA driver for WSL2** installed on the
  Windows side (not inside WSL — NVIDIA's WSL driver exposes the GPU to
  Linux automatically). Verify with `nvidia-smi` inside WSL.
- ~25GB free disk (16GB model weights + venv + caches).
- [`uv`](https://docs.astral.sh/uv/) installed inside WSL.

## 1. Clone both repositories

```bash
cd ~
git clone https://github.com/Skan22/Sentinel_Starter_Kit.git
git clone git@github.com:sabri-journey/IndabaX.git
```

(If SSH isn't set up for GitHub on this machine yet, use the HTTPS clone URL
for the second one instead: `https://github.com/sabri-journey/IndabaX.git`.)

## 2. Set up the starter kit + apply the 4-bit fix

```bash
cd ~/Sentinel_Starter_Kit
uv sync --extra hf
uv pip install bitsandbytes   # not part of the hf extra; needed for 4-bit
```

Apply the fix (already committed as a patch file in the defense repo — the
starter kit itself is the organizer's read-only upstream, so this stays a
local, uncommitted change here, exactly like quantization/dtype/precision
choices the participant guide says are yours to configure):

```bash
git apply ~/IndabaX/docs/patches/hf_adapter_4bit.patch
```

**What the patch does and why** (full detail in the patch file's own
comments): the original `HFModelAdapter` had no quantization support at
all. A first attempt added 4-bit + `llm_int8_enable_fp32_cpu_offload=True`
+ a tight `max_memory` budget — but that flag is an **8-bit-only**
feature; combined with 4-bit it made `accelerate` swap CPU-offloaded
4-bit layers back onto GPU mid-generation, which crashes
(`NotImplementedError: Cannot copy out of meta tensor; no data!`) because
bitsandbytes' NF4 quantization state can't rematerialize that way. The
patch removes CPU offload entirely and pins the whole model to `cuda:0`
(`device_map={"": 0}`) with double-quantization enabled — the model fits
entirely on an 8GB card this way, no offload needed, so this failure mode
never triggers.

## 3. Download the weights

```bash
huggingface-cli download Qwen/Qwen3-8B
```

Qwen3-8B is Apache-2.0 and not gated, so this shouldn't need a token. ~16GB,
will take a while depending on bandwidth.

## 4. Smoke-test the model loads and generates

```bash
cd ~/Sentinel_Starter_Kit
SENTINEL_4BIT=1 uv run python -c "
from sentinel.models.hf_adapter import HFModelAdapter
m = HFModelAdapter(enable_thinking=False)
prompt = m._tokenizer.apply_chat_template(
    [{'role':'user','content':'Reply with exactly: {\"type\":\"respond\",\"content\":\"hi\",\"final\":true}'}],
    tokenize=False, add_generation_prompt=True, enable_thinking=False)
inputs = m._tokenizer([prompt], return_tensors='pt').to(m._model.device)
out = m._model.generate(**inputs, max_new_tokens=20, do_sample=False)
print(m._tokenizer.decode(out[0][inputs['input_ids'].shape[-1]:], skip_special_tokens=True))
"
```

If this OOMs even on 8GB: lower `max_new_tokens`/context first before
concluding it doesn't fit — see the patch file's comments for the exact
memory arithmetic. If it still doesn't fit, that's new information worth
reporting back before going further.

**Important**: `SENTINEL_4BIT=1` must be set in the environment for every
command below that launches the reference agent (`sentinel eval`,
`sentinel run`) — the CLI's `_model_factory("qwen3-8b")` doesn't take extra
kwargs, so quantization is switched on by this env var inside the patched
adapter, not by a CLI flag.

## 5. Set up and start our defense

```bash
cd ~
git clone git@github.com:sabri-journey/IndabaX.git   # if not already done
cd IndabaX
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
PYTHONPATH=src uvicorn defense.adapter:app --port 8080 &
curl -s http://127.0.0.1:8080/healthz   # expect {"status":"ok"}
```

## 6. Run the real validation

From the starter kit, with the defense above running:

```bash
cd ~/Sentinel_Starter_Kit
SENTINEL_4BIT=1 uv run sentinel eval public --defense-url http://127.0.0.1:8080 --model qwen3-8b --json > ~/IndabaX/results/eval_public_qwen3.json
SENTINEL_4BIT=1 uv run sentinel eval validation --defense-url http://127.0.0.1:8080 --model qwen3-8b --json > ~/IndabaX/results/eval_validation_qwen3.json
python3 -c "
import json
for f in ['eval_public_qwen3','eval_validation_qwen3']:
    d = json.load(open(f'/home/$(whoami)/IndabaX/results/{f}.json'))
    print(f, json.dumps(d['metrics'], indent=2))
"
```

This will be much slower than mock (real generation per step, on GPU but
still an 8B model) — budget real time, not seconds, per scenario.

Compare these numbers honestly against the mock-model results in
`results/RESULTS_SUMMARY.md`. The architecture doc's own warning: a defense
can look stronger against mock than the real model, because the mock
model's directive grammar is a simplified simulation of susceptibility. If
qwen3-8b's ASR/BTU/FBR/UER differ meaningfully from mock, that's real,
important, reportable evidence either way — do not tune the defense to chase
a specific number here; report what happens.

## 7. Capture the demo traces for the video

Pick 3-4 scenarios that best tell the story on camera (one benign task
completing cleanly, one clear attack caught, one hard negative passing, and
ideally one multi-step/long-horizon scenario if the risk trajectory chart
should show a climb):

```bash
cd ~/Sentinel_Starter_Kit
rm -rf ~/IndabaX/traces   # start clean so the observability dashboard only shows this run

SENTINEL_4BIT=1 uv run sentinel run --scenario scenarios/public/finance/finance_false_approval.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b

SENTINEL_4BIT=1 uv run sentinel run --scenario scenarios/public/enterprise/enterprise_poisoned_invoice.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b

SENTINEL_4BIT=1 uv run sentinel run --scenario scenarios/public/soc/soc_confirmed_isolation.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b

# add one more if a good multi-step example presents itself, e.g.:
SENTINEL_4BIT=1 uv run sentinel run --scenario scenarios/public/soc/soc_hostile_log_text.yaml \
  --defense-url http://127.0.0.1:8080 --model qwen3-8b
```

Then open the dashboard and load each trace (from `~/IndabaX/traces/*.jsonl`)
for the recording:

```bash
cd ~/IndabaX && python3 -m http.server 8877 &
# open http://127.0.0.1:8877/observability/index.html in a browser,
# drag in a trace file, or use ?trace=../traces/<session_key>.jsonl&expand=all
```

## 8. What to report back / write down for the technical report

- The exact commands above, and how long the model actually took to load
  and run per scenario (for the report's reproducibility section).
- Whether `enable_thinking=False` was needed (it is, by default in the
  patch) or whether thinking mode + a higher `max_new_tokens` worked better
  — the participant guide says either is acceptable, just declare which.
- The qwen3-8b eval metrics next to the mock-model ones in
  `results/RESULTS_SUMMARY.md` — add a row, don't just replace the mock
  numbers; both are evidence.
- Any qwen3-8b-specific failure you see that mock never exercised (the mock
  model's directive grammar is simpler than what a real model might
  produce) — this is exactly the kind of honest finding the failure-analysis
  section of the report rewards.
- The 3-4 trace files from step 7, copied somewhere durable (they're what
  the video is recorded from).
