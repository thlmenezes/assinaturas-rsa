import random, math, utilidade

def gerarChaves(tamanho:int = 1024):
    # Gera p e q, caso nescessário
    p = utilidade.geradorPrimo(tamanho)
    q = utilidade.geradorPrimo(tamanho)
    while p == q:
        q = utilidade.geradorPrimo(tamanho)
    print(f'p: {p}')
    print(f'q: {q}')
    print(f'n: {p*q}')
    print(f'euler: {(p-1)*(q-1)}')
    # Calcula n e a função totiente de euler
    n = p*q
    euler = (p-1)*(q-1)

    # Gera as chaves
    public_key = random.randrange(1,euler-1)
    while math.gcd(public_key,euler) != 1 or pow(public_key,-1, euler) == public_key:
        public_key = random.randrange(1,euler-1)
    private_key = pow(public_key,-1, euler)
    #private_key = utilidade.invM2(public_key, euler)          #Outra opção para o inverso multiplicativo modular
    print(public_key*private_key%euler)
    return public_key, private_key, n

def encrypt(e, n, message):
    cipher = ''
    for c in message:
        m = ord(c)
        cipher += str(pow(m,e,n)) + ' '
    return cipher
    """ return ''.join((chr((ord(x)**e)%n))for x in message) """

def decrypt(d, n, cipher):
    msg = ''
    
    parts = cipher.split()
    for part in parts:
        if part:
            c = int(part)
            msg += chr(pow(c,d,n))
    return msg
    """ return ''.join(chr((ord(x)**d)%n) for x in cipher) """

    