import os
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


OSINT_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = OSINT_ROOT.parent
sys.path.insert(0, str(OSINT_ROOT))
sys.path.insert(0, str(REPO_ROOT))

from inference import OSINTInference
from bdu_adapter import BDUAdapter, BDUAdapterError


app = FastAPI(title="OSINT Neural Network API", version="1.0.0")
_inference: Optional[OSINTInference] = None
_bdu_adapter: Optional[BDUAdapter] = None


class OSINTQueryRequest(BaseModel):
    query: str = Field(..., min_length=3, description="OSINT запрос")
    include_tools: bool = True
    use_cyberintel: bool = True


class OSINTQueryWithBDURequest(BaseModel):
    query: str = Field(..., min_length=3, description="OSINT запрос")
    vulnerability_id: Optional[int] = None
    cve_id: Optional[str] = None
    bdu_id: Optional[str] = None
    include_tools: bool = True
    use_cyberintel: bool = True


def _get_inference() -> OSINTInference:
    global _inference
    if _inference is None:
        model_path = os.getenv("OSINT_MODEL_PATH", str(OSINT_ROOT / "models" / "final_model"))
        use_lora = os.getenv("OSINT_USE_LORA", "false").lower() in ("1", "true", "yes")
        base_model = os.getenv("OSINT_BASE_MODEL", "mistralai/Mistral-7B-v0.1")
        _inference = OSINTInference(
            model_path=model_path,
            use_lora=use_lora,
            base_model=base_model,
        )
    return _inference


def _get_bdu_adapter() -> BDUAdapter:
    global _bdu_adapter
    if _bdu_adapter is None:
        _bdu_adapter = BDUAdapter()
    return _bdu_adapter


@app.get("/health")
def health() -> Dict[str, Any]:
    return {"status": "ok"}


@app.post("/osint/query")
def osint_query(payload: OSINTQueryRequest) -> Dict[str, Any]:
    inference = _get_inference()
    try:
        result = inference.process_osint_query(
            query=payload.query,
            include_tools=payload.include_tools,
            use_cyberintel=payload.use_cyberintel,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return {"success": True, "data": result}


@app.post("/osint/query-with-bdu")
def osint_query_with_bdu(payload: OSINTQueryWithBDURequest) -> Dict[str, Any]:
    inference = _get_inference()
    adapter = _get_bdu_adapter()
    try:
        result = inference.process_osint_query(
            query=payload.query,
            include_tools=payload.include_tools,
            use_cyberintel=payload.use_cyberintel,
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    try:
        bdu_row = adapter.build_bdu_row(
            vulnerability_id=payload.vulnerability_id,
            cve_id=payload.cve_id,
            bdu_id=payload.bdu_id,
        )
    except BDUAdapterError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    return {
        "success": True,
        "data": {
            "osint_result": result,
            "bdu_excel_row": bdu_row,
        },
    }


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("OSINT_API_HOST", "0.0.0.0")
    port = int(os.getenv("OSINT_API_PORT", "8010"))
    uvicorn.run(app, host=host, port=port)
