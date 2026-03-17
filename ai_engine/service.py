from fastapi import FastAPI

app = FastAPI(title="CyberRakshak AI Engine", version="2.0.0")


@app.get("/health")
def health():
    return {"status": "ok", "service": "cyberrakshak-ai-engine"}


@app.get("/api/anomaly/info")
def anomaly_info():
    return {
        "detectors": ["IsolationForest", "OneClassSVM"],
        "description": "Unsupervised anomaly detectors for unknown cybersecurity threats.",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)
