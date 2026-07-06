from langgraph.graph import StateGraph, END

# Minimal agent surface. Credentials are read from the environment at runtime;
# the committed .env.example is a template of empty placeholders, not secrets.
graph = StateGraph(dict)
