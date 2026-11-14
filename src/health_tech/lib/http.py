"""HTTP helpers shared by the routers."""

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel


class AbortError(Exception):
    """Stops the request and responds with status_code and a JSON body."""

    def __init__(self, status_code: int, content: dict[str, str]) -> None:
        super().__init__(status_code, content)
        self.status_code = status_code
        self.content = content


class BindError(ValueError):
    """The request body is not valid JSON for the target model."""


async def bind_json[T: BaseModel](request: Request, model: type[T]) -> T:
    """Parse and validate the JSON request body into model."""
    try:
        return model.model_validate(await request.json())
    except ValueError as exc:
        raise BindError(str(exc)) from exc


def new_app(title: str) -> FastAPI:
    """Create a FastAPI app that renders AbortError as a JSON response."""
    app = FastAPI(title=title)

    @app.exception_handler(AbortError)
    async def abort_handler(_: Request, exc: AbortError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code, content=exc.content)

    return app
