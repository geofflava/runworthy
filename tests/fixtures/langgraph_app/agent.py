from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver
from langchain_core.tools import tool
import subprocess, requests

@tool
def run_shell(cmd: str) -> str:
    "Run a shell command."
    return subprocess.run(cmd, shell=True, capture_output=True, text=True).stdout

def call_api(url):
    return requests.get(url).text

graph = StateGraph(dict)
memory = MemorySaver()
