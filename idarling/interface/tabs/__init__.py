from .general import _TabCfgGeneral
from .network import _TabCfgNetwork
from .servers import _TabCfgServer


def cfg_server(program, parent):
    return _TabCfgServer(program, parent).get()


def cfg_general(program, parent):
    return _TabCfgGeneral(program, parent).get()


def cfg_network(program, parent):
    return _TabCfgNetwork(program, parent).get()
