from fastapi import FastAPI, Request
from fastapi.responses import StreamingResponse
from fastapi.staticfiles import StaticFiles
import json
import asyncio
from iot_defense.demo.controller import DemoController

app = FastAPI()
controller = DemoController()

app.mount("/static", StaticFiles(directory="data/dashboard/static"), name="static")

@app.get("/stream")
async def message_stream(request: Request):
    async def event_generator():
        while True:
            state = await controller.event_queue.get()
            yield f"data: {json.dumps(state)}\n\n"
    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/state")
async def get_state():
    with open(controller.state_file, "r") as f:
        return json.load(f)
