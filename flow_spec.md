
# ida
match = [
    ip de origgem
    porta de origem
    ip de destino
    porta de destino
]

action = [
    ip de destino = ip selecionado
    mac de destino = mac selecionado
]

# volta
match = [
    ip selecionado
    porta de destino
    ip de origem
    porta de origem
]

action = [
    ip de destino novo = ip de destino,
    mac de destino novo = mac de destino
]