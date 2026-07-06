from crewai import Agent, Crew, Task

researcher = Agent(role="researcher", goal="find", backstory="curious")
crew = Crew(agents=[researcher], tasks=[])
