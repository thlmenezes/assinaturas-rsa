import RSA
import AES_CTR

if __name__ == '__main__':
    while True:
        print('='*7, 'MENU','='*7)

        print("1 - Cifrar e Decifra com RSA")
        print("2 - Cifrar mensagem com AES modo CTR")
        print("3 - Decifrar mensagem com AES modo CTR")
        print("0 - Sair")
        op = int(input("Escolha uma opcao: "))
        
        if(op == 1):
            print('Digite o texto:')
            msg = input()

            Pk, Sk, n= RSA.gerarChaves(1024)
            print(f'Chave Pública: {Pk}\n')
            print(f'Chave Privada: {Sk}\n')
        
            enc = RSA.encrypt(Pk,n,msg)
            dec = RSA.decrypt(Sk,n,enc)
            print('Mensagem Encriptada: ', enc, '\n')
            print('Mensagem Decriptada: ', dec, '\n')
        elif(op == 2):
            AES_CTR.EncryptarCTR()
        elif(op == 3):
            AES_CTR.DecryptarCTR()
        elif(op == 0):
            break
        else:
            print('\n\nOpção Inválida!\n\n')