# Runbook — serving Foundation-Sec-8B-Reasoning with llama.cpp

ForgeShield OT's AI analyst talks to an **OpenAI-compatible** chat endpoint. The default
stack serves `fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF` (a 4-bit ~4.92 GB GGUF,
cybersecurity-specialized, *reasoning* model) with **llama.cpp** `llama-server`, which
exposes `/v1/chat/completions`, `/v1/models` and `/health`.

The model is public — **no Hugging Face token is required**.

---

## 1. Get the model (once)

The GGUF lives in the `llama-models` Docker named volume (ext4 inside the WSL2 VM). Do
**not** bind-mount it from a Windows drive (`/mnt/c/...`) — 9p I/O is far too slow for a
~5 GB weight file and model load will crawl.

```bash
make llama-pull
```

This downloads the GGUF into `forgeshield-ot_llama-models:/models/`. Alternative: let
`llama-server` auto-download on first boot by replacing `--model …` with
`-hf fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF` in the compose `command` (slower
first start; needs network at runtime).

> If `make llama-pull` saves an HTML page instead of a GGUF, the filename changed —
> check the repo's *Files* tab and override `LLAMA_GGUF=<name>.gguf make llama-pull`.

## 2. Start the stack

### GPU (NVIDIA) — recommended

Requires an NVIDIA GPU and the **NVIDIA Container Toolkit** working in WSL2
(`docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi` should print
your GPU).

```bash
make llama-pull        # if not already done
make up-gpu            # docker compose -f docker-compose.yml -f docker-compose.gpu.yml up --build -d
```

All layers offload to the GPU (`--n-gpu-layers 99`); answers take a few seconds.

### CPU — portable fallback

```bash
make llama-pull
make up                # plain docker compose up; the base `llama` service is CPU-only
```

Set `LLAMA_THREADS` to your physical core count in `.env`. Expect tens of seconds to ~a
minute per reasoning answer; the first request after boot also pays model-load time.

### Host-run `llama-server` (you manage the process)

```bash
llama-server -hf fdtn-ai/Foundation-Sec-8B-Reasoning-Q4_K_M-GGUF \
  --alias Foundation-Sec-8B-Reasoning \
  --host 0.0.0.0 --port 8080 \
  --ctx-size 8192 --n-predict 2048 \
  --jinja --reasoning-format deepseek \
  --n-gpu-layers 99            # omit on CPU-only hosts
```

Then set `AI_BASE_URL=http://host.docker.internal:8080/v1` in `.env` and start the rest of
the stack without the bundled `llama` service.

## 3. Launch flags that matter

| Flag | Why |
|------|-----|
| `--alias Foundation-Sec-8B-Reasoning` | The served model id **must equal `AI_MODEL_NAME`**, or the provider's request 4xxs → `ConfigurationError` → 503. |
| `--jinja --reasoning-format deepseek` | Use the model's chat template and split the `<think>` block into a separate `reasoning_content` field (surfaced in the UI). |
| `--ctx-size 8192` | Room for the RAG data block (≤30 records) + reasoning + answer. |
| `--n-predict 2048` | Completion budget; reasoning + answer share it. Matches `AI_MAX_TOKENS`. |
| `--n-gpu-layers 99` | GPU only — offload all layers (override file). |

## 4. Verify

```bash
curl -s localhost:8080/health                 # {"status":"ok"} once the model is loaded
curl -s localhost:8080/v1/models | jq .        # lists "Foundation-Sec-8B-Reasoning"
# In the app:
curl -s localhost:8000/api/ai/health -H "Authorization: Bearer <token>"
#  -> { "provider":"local_foundation_sec", "model":"Foundation-Sec-8B-Reasoning", "healthy":true }
make llama-logs                                # tail the inference server
```

Then exercise a real query, e.g. `POST /api/assets/{id}/ai-attack-path`, and confirm a
populated, cited `attack_path` with a captured reasoning trace.

## 5. Output mode (`AI_JSON_MODE`)

This is a **reasoning** model, so the default is `AI_JSON_MODE=off`: the model thinks in
`<think>` then emits JSON, which the server extracts robustly (`validate_answer`). Do
**not** set `json_object`/`json_schema` for this model — a JSON grammar applied from the
first token suppresses the reasoning and degrades quality. Those modes are for
non-reasoning OpenAI-compatible servers only.

## 6. Troubleshooting

| Symptom | Likely cause / fix |
|---------|--------------------|
| `/api/ai/health` → `healthy:false`, AI endpoints 503 | Model still loading (watch `make llama-logs`), wrong `AI_BASE_URL`, or `--alias` ≠ `AI_MODEL_NAME`. |
| `llama` container restarts / OOM | Not enough RAM/VRAM. On CPU raise WSL2 RAM in `.wslconfig`; on GPU lower `--n-gpu-layers` or `--ctx-size`. |
| GPU not used (`nvidia-smi` idle) | NVIDIA Container Toolkit not configured in WSL2, or you ran `make up` (CPU) instead of `make up-gpu`. |
| Very slow first answer | Cold model load + cache warmup; subsequent calls are faster. `AI_TIMEOUT_SECONDS=180` covers it. |
| GPU loaded but inference ~2-5 tok/s; UI shows "Cannot reach the API" | **Laptop dGPU power cap.** Check `docker run --rm --gpus all nvidia/cuda:12.4.0-base-ubuntu22.04 nvidia-smi -q -d CLOCK,PERFORMANCE,POWER`: if `Performance State: P8`, `SW Power Cap: Active`, and `Current Power Limit` ≪ Default (e.g. 15 W vs 65 W) with SM clock pinned ~180 MHz, the GPU is throttled by host power management. Fix on the **Windows host**: plug into **AC power**, set Windows Power mode to *Best performance*, set the vendor utility's GPU/TGP mode to *Performance/Turbo*, and NVIDIA Control Panel → Manage 3D settings → Power management mode → *Prefer maximum performance*. The "Cannot reach the API" message is the frontend's 90 s axios timeout firing because the throttled GPU can't finish in time — not a backend outage. |
| Healthcheck shows `unhealthy` but it works | The base image may lack `curl`; the backend degrades gracefully regardless (`depends_on` uses `service_started`, not `service_healthy`). |
| Need to run fully offline / no model | Set `AI_PROVIDER=mock` — every AI feature works with the deterministic mock. |
