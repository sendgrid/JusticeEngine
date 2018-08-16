__all__ = []
import pkgutil
import inspect

# This init is used to ensure every AbstractAlerter implementation from this directory
for loader, name, is_pkg in pkgutil.walk_packages(__path__):
    module = loader.find_module(name).load_module(name)
    for name, value in inspect.getmembers(module):
        # ignore the __init__s and other fun python isms.
        if name.startswith('__'):
            continue
        # only import classes that are implementations of AbstractAlerter
        elif 'alert' in dir(value) and "AbstractAlerter" in str(value.__base__):
            globals()[name] = value
            __all__.append(name)
