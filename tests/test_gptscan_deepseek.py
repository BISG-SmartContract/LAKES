from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace

import pytest


ROOT = Path(__file__).resolve().parents[1]
GPTSCAN_SOURCE = ROOT / "docker" / "vendor" / "gptscan" / "src"


def _load_chat_module(monkeypatch):
    calls: list[dict] = []

    error_module = ModuleType("openai.error")
    for name in (
        "RateLimitError",
        "APIConnectionError",
        "Timeout",
        "APIError",
    ):
        setattr(error_module, name, type(name, (Exception,), {}))

    openai_module = ModuleType("openai")
    openai_module.__path__ = []
    openai_module.error = error_module
    openai_module.InvalidRequestError = type(
        "InvalidRequestError",
        (Exception,),
        {},
    )
    openai_module.api_key = None
    openai_module.api_base = None

    class FakeChatCompletion:
        @staticmethod
        def create(**kwargs):
            calls.append(kwargs)
            return {"choices": [{"message": {"content": "{}"}}]}

    openai_module.ChatCompletion = FakeChatCompletion

    class FakeEncoder:
        @staticmethod
        def encode(value: str) -> list[int]:
            return list(range(len(value)))

    tiktoken_module = ModuleType("tiktoken")
    tiktoken_module.get_encoding = lambda _name: FakeEncoder()
    tiktoken_module.encoding_for_model = lambda _name: FakeEncoder()

    config_module = ModuleType("config")
    config_module.OPENAI_APIS = []
    config_module.GPT4_API = ""

    console = SimpleNamespace(print=lambda *_args, **_kwargs: None)
    rich_module = ModuleType("rich")
    rich_module.get_console = lambda: console
    rich_utils_module = ModuleType("rich_utils")
    rich_utils_module.make_response_panel = lambda *_args, **_kwargs: None

    monkeypatch.setitem(sys.modules, "openai", openai_module)
    monkeypatch.setitem(sys.modules, "openai.error", error_module)
    monkeypatch.setitem(sys.modules, "tiktoken", tiktoken_module)
    monkeypatch.setitem(sys.modules, "config", config_module)
    monkeypatch.setitem(sys.modules, "rich", rich_module)
    monkeypatch.setitem(sys.modules, "rich_utils", rich_utils_module)

    module_name = "_lakes_test_gptscan_chatgpt_api"
    spec = importlib.util.spec_from_file_location(
        module_name,
        GPTSCAN_SOURCE / "chatgpt_api.py",
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, module_name, module)
    spec.loader.exec_module(module)
    return module, calls


def test_official_deepseek_gptscan_json_call_is_non_thinking_json_mode(
    monkeypatch,
) -> None:
    module, calls = _load_chat_module(monkeypatch)
    monkeypatch.setenv("OPENAI_API_BASE", "https://api.deepseek.com")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("GPTSCAN_MODEL_GPT4", "deepseek-v4-flash")

    assert module.Chat().sendMessages("Return JSON.", GPT4=True, json_mode=True) == "{}"

    assert len(calls) == 1
    assert calls[0]["model"] == "deepseek-v4-flash"
    assert calls[0]["temperature"] == 0
    assert calls[0]["thinking"] == {"type": "disabled"}
    assert calls[0]["response_format"] == {"type": "json_object"}


def test_official_deepseek_gptscan_text_call_disables_thinking_without_json_mode(
    monkeypatch,
) -> None:
    module, calls = _load_chat_module(monkeypatch)
    monkeypatch.setenv("OPENAI_API_BASE", "https://api.deepseek.com/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    module.Chat().sendMessages("Answer Yes or No.", GPT4=True)

    assert calls[0]["thinking"] == {"type": "disabled"}
    assert "response_format" not in calls[0]


def test_custom_gptscan_host_receives_no_deepseek_only_request_fields(
    monkeypatch,
) -> None:
    module, calls = _load_chat_module(monkeypatch)
    monkeypatch.setenv("OPENAI_API_BASE", "https://example.test/v1")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")

    module.Chat().sendMessages("Return JSON.", GPT4=True, json_mode=True)

    assert "thinking" not in calls[0]
    assert "response_format" not in calls[0]


def _load_pipeline(monkeypatch):
    chat, calls = _load_chat_module(monkeypatch)
    monkeypatch.setenv("OPENAI_API_BASE", "https://api.deepseek.com")
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("GPTSCAN_USE_GPT4", "true")

    def respond(**kwargs):
        calls.append({**kwargs, "messages": [dict(message) for message in kwargs["messages"]]})
        prompt = kwargs["messages"][-1]["content"]
        if "response_format" in kwargs:
            payload = {"1": "Yes"} if prompt.startswith("JSON:") else {"answer": ["value"]}
            content = json.dumps(payload)
        else:
            content = "Yes"
        return {"choices": [{"message": {"content": content}}]}

    monkeypatch.setattr(sys.modules["openai"].ChatCompletion, "create", staticmethod(respond))
    chat_module = ModuleType("chatgpt_api")
    chat_module.Chat = chat.Chat
    templates = ModuleType("query_template")
    templates.prompt_single_yes_no_question = lambda _question, source: "TEXT:" + source
    templates.prompt_multiple_choice_scenarios = lambda _questions, source: "JSON:" + source
    utils = ModuleType("utils")
    utils.split_answer_section = lambda response: response
    antlr = ModuleType("antlr4helper")
    antlr.__path__ = []
    antlr.parseString = lambda _source: None
    callgraph = ModuleType("antlr4helper.callgraph")
    callgraph.CallGraph = type("CallGraph", (), {})
    for name, module in (
        ("chatgpt_api", chat_module), ("query_template", templates), ("utils", utils),
        ("antlr4helper", antlr), ("antlr4helper.callgraph", callgraph),
    ):
        monkeypatch.setitem(sys.modules, name, module)
    monkeypatch.setattr(sys.modules["rich_utils"], "make_prompt_panel", lambda *_a: None, raising=False)
    spec = importlib.util.spec_from_file_location(
        "_lakes_test_gptscan_pipeline", GPTSCAN_SOURCE / "analyze_pipeline.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    class ImmediatePool:
        def __init__(self, **kwargs):
            pass

        def apply_async(self, function, args=(), kwds=None):
            return SimpleNamespace(ready=lambda: True, get=lambda: function(*args, **(kwds or {})))

        def close(self):
            pass

        def terminate(self):
            pass

        def join(self):
            pass

    monkeypatch.setattr(module.multiprocessing, "Pool", ImmediatePool)
    return module, calls


@pytest.mark.parametrize("single", [False, True], ids=["multiple-values", "single-value"])
def test_gptscan_static_json_callers_request_and_parse_json(monkeypatch, single) -> None:
    module, calls = _load_pipeline(monkeypatch)
    if single:
        assert module.ask_for_static_json_single("find values", "source", "answer") == {"answer": ["value"]}
    else:
        answer, raw = module.ask_for_static_json("find values", "source", ["answer"])
        assert answer == {"answer": "value"}
        assert raw == {"answer": ["value"]}
    assert calls
    assert all(call.get("response_format") == {"type": "json_object"} for call in calls)


def test_gptscan_scenario_and_caller_paths_request_json(tmp_path, monkeypatch) -> None:
    module, calls = _load_pipeline(monkeypatch)
    source = tmp_path / "Probe.sol"
    source.write_text(
        "contract Probe {\nfunction target() public {\nreturn;\n}\n"
        "function caller() public {\ntarget();\n}\n}\n"
    )
    target = {"name": "target", "visibility": "public", "loc": {"start": "2:0", "end": "4:0"}}
    caller = {"name": "caller", "visibility": "public", "loc": {"start": "5:0", "end": "7:0"}}
    caller_key = (str(source), "Probe", "caller")
    graph = SimpleNamespace(
        files={str(source): {"subcontracts": [{"name": "Probe", "functions": [target]}]}},
        get_callers=lambda _name: [caller_key],
        get_function_detail=lambda *_args: caller,
    )
    monkeypatch.setattr(module, "CallGraph", lambda _folder: graph)
    rule = {"name": "probe-rule", "functions": ["target"], "property": ["scenario", "question"]}
    result, _graph, _metadata = module.ask_whether_has_vul_with_scenario_v9(str(tmp_path), [rule])
    findings = result[str(source)]["Probe"]["target"]
    assert findings["__ONLY_FUNCTION__"]["data"] == [rule]
    assert findings["!!!".join(caller_key)]["data"] == [rule]
    structured = [call for call in calls if call["messages"][-1]["content"].startswith("JSON:")]
    assert len(structured) == 2
    assert all(call.get("response_format") == {"type": "json_object"} for call in structured)
