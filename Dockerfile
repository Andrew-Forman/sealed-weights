FROM pytorch/pytorch:2.5.1-cuda12.4-cudnn9-runtime

# Pinned to the exact versions tested locally on CPU (see README).
RUN pip install --no-cache-dir \
    transformers==4.51.3 peft==0.15.2 accelerate==1.6.0 \
    fastapi==0.115.12 "uvicorn[standard]==0.34.2" cryptography==44.0.2

WORKDIR /srv
COPY app /srv/app

# The enclave root filesystem is read-only; /tmp and /root are tmpfs (see tinfoil-config.yml).
ENV HF_HOME=/tmp/hf PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 \
    HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
EXPOSE 8000
CMD ["uvicorn", "app.app:app", "--host", "0.0.0.0", "--port", "8000"]
