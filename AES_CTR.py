import unicodedata
import utilidade
import random
import string

def GetPlaintext(nonce, count):
    bloco = []
    str1 = str(count)
    while(len(str1) < 8):
        str1 = '0' + str1

    str1 = nonce + str1

    a = bytes(str1, 'ascii')

    for i in range(16):
        bloco.append(a[i])

    return bloco

def EncryptarCTR():
    n = 10
    """ 
    n = int(input("Digite o número de rodadas (máximo de 13): "))
    while(n > 13):
        n = input("Número de rodadas maior do que 13, informe outra: ")
    """
    
    msg = input("Digite a mensagem em claro: ").encode('utf-8')
    
    """ op_chave = input("Deseja inserir uma chave (s/n): ")
    if(op_chave in 'SIMsimYESyes'):
        chave = input("Informe a chave com tamanho de até 16 caracteres: ")
        while(len(chave) > 16):
            chave = input("Chave maior que 16 caracteres, informe outra: ")
        chave = chave + bytes(16-len(chave)).decode('utf-8')
    else:
        chave = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
        print('Chave gerada: ', chave) """
    
    #chave = ''.join(random.choice(string.ascii_letters) for _ in range(16))
    chave = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(16))
    print('Chave gerada:', chave)
    chave = bytes(chave, 'ascii')
    chave_aux = []
    for i in range(16):
        chave_aux.append(chave[i])
    #print('Chave_aux gerada:', chave_aux)
        
    cifrado = []
    
    nonce = ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))
    print("OFFSET gerado:", nonce, ' ----> Guarde-a caso queira decifrar')
        
    block = utilidade.CreateBlock(msg)
    #print('Bloco gerado:',block)

    for i in range(len(block)):
        
        #print('Bloco', i)
        
        key = chave_aux
        block_aux = GetPlaintext(nonce, i)
        #print('Plaintext:', block_aux)

        block_aux = utilidade.AddRoundKey(block_aux, key)  # primeira iteracao
        #print(block_aux)
        for j in range(0, n-1):
            block_aux = utilidade.SubBytes(block_aux)  # conversao do bloco utilizando a sbox
            block_aux = utilidade.ShiftRows(block_aux)  # shift left das 'linhas'
            block_aux = utilidade.MixColumn(block_aux)  # embaralha os elementos por coluna
            key = utilidade.KeyExpansion(key, j)  # pega nova chave
            block_aux = utilidade.AddRoundKey(block_aux, key)
            #print(block_aux)

        if(n != 0):
            block_aux = utilidade.SubBytes(block_aux)
            block_aux = utilidade.ShiftRows(block_aux)
            key = utilidade.KeyExpansion(key, n-1)
            block_aux = utilidade.AddRoundKey(block_aux, key)
            #print(block_aux)
        cifrado.append(utilidade.MakeXor(block_aux, block[i]))
        #print('Cifrado_list:', cifrado)
    cifrado = ''.join(''.join(str(x)+' ' for x in bloco) for bloco in cifrado)
    print('Mensagem Cifrada:', cifrado,'\n\n')
    
    return 0

def DecryptarCTR():
    n = 10
    #round = int(input("Digite o número de rodadas [9-13]: "))
    
    msg = input("Digite a mensagem cifrada: ").split()
    aux, block = [],[]
    for j in range(0, len(msg), 16):
        for i in range(16):
            aux.append(int(msg[i+j]))
        block.append(aux)
        aux = []


    chave = input("Informe a chave com tamanho de até 16 caracteres: ")
    while(len(chave) > 16):
        chave = input("Chave maior que 16 caracteres, informe outra: ")
    chave = bytes(chave, 'ascii')
    
    chave_aux = []
    for i in range(16):
        chave_aux.append(chave[i])
        
    cifrado = []
    
    nonce = input("Informe o OFFSET: ")

    #block = utilidade.CreateBlock(msg)

    """ for i in range(len(block)):
        block_aux = GetPlaintext(nonce, i)
        
        inv_key = []
        aux = chave_aux
        inv_key.append(aux)
        for j in range(n):
            aux = utilidade.KeyExpansion(aux, j)
            inv_key.append(aux)
        print(inv_key)
        a = n
        block_aux = utilidade.AddRoundKey(block_aux, inv_key[n])
        while(a > 0):
            if(a > 1):
                block_aux = utilidade.SubBytesInv(block_aux)
                block_aux = utilidade.ShiftRowsInv(block_aux)
                block_aux = utilidade.AddRoundKey(block_aux, inv_key[a-1])
                block_aux = utilidade.InvMixColumn(block_aux)
            else:
                block_aux = utilidade.ShiftRowsInv(block_aux)
                block_aux = utilidade.SubBytesInv(block_aux)
                block_aux = utilidade.AddRoundKey(block_aux, inv_key[0])
            a -= 1
        
        cifrado.append(utilidade.MakeXor(block_aux, block[i])) """
        
    for i in range(len(block)):
        
        #print('Bloco', i)
        
        key = chave_aux
        block_aux = GetPlaintext(nonce, i)
        #print('Plaintext:', block_aux)

        block_aux = utilidade.AddRoundKey(block_aux, key)  # primeira iteracao
        #print(block_aux)
        for j in range(0, n-1):
            block_aux = utilidade.SubBytes(block_aux)  # conversao do bloco utilizando a sbox
            block_aux = utilidade.ShiftRows(block_aux)  # shift left das 'linhas'
            block_aux = utilidade.MixColumn(block_aux)  # embaralha os elementos por coluna
            key = utilidade.KeyExpansion(key, j)  # pega nova chave
            block_aux = utilidade.AddRoundKey(block_aux, key)
            #print(block_aux)

        if(n != 0):
            block_aux = utilidade.SubBytes(block_aux)
            block_aux = utilidade.ShiftRows(block_aux)
            key = utilidade.KeyExpansion(key, n-1)
            block_aux = utilidade.AddRoundKey(block_aux, key)
            #print(block_aux)
        cifrado.append(utilidade.MakeXor(block_aux, block[i]))
        
    cifrado = ''.join(''.join(chr(x) for x in bloco) for bloco in cifrado)
    print('Mensagem Decifrada:', cifrado,'\n\n')
    return 0