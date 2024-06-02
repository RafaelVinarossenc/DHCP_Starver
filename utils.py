import random
import string

def get_random_mac():
    """
    Returns a string with a "random" MAC address
    """
    mac = "34:" # Our bogus MAC addresses starts with 34 to make it easier to track/debug
    for i in range(10):
        num = random.randint(0, 15)
        if num < 10:
            num = chr(48 + num)
        else:
            num = chr(87 + num)
        mac += num
        if i % 2 == 1:
            mac += ":"
    return mac[:-1]

def get_random_hostname():
    """
    Returns a random string like "DESKTOP-XXXXXXX"
    """
    # Definir los caracteres permitidos (letras mayúsculas y dígitos)
    chars = string.ascii_uppercase + string.digits
    
    # Generar una cadena aleatoria de 7 caracteres
    random_string = ''.join(random.choice(chars) for _ in range(7))
    
    # Devolver el resultado con el prefijo "DESKTOP-"
    return "DESKTOP-" + random_string