import os

# For loading scripts dynamically
for module in os.listdir(os.path.dirname(__file__)):
    if module == '__init__.py' or module[-3:] != '.py':
        continue
    __import__(('scripts.slingshot.'+module[:-3]).lower(), locals(), globals())