import RSA
import AES_CTR
import validador

if __name__ == '__main__':
    while True:
        print('='*7, 'MENU','='*7)

        print("1 - Cifrar e Decifra com RSA")
        print("2 - Cifrar mensagem com AES modo CTR")
        print("3 - Decifrar mensagem com AES modo CTR")
        print("0 - Sair")
        op = int(input("Escolha uma opcao: "))
        
        if(op == 1):
            Pk_A, Sk_A, n_A, chave_pub_A, chave_priv_A = RSA.gerarChaves(1024)
            print(f'A:Chave Pública: {Pk_A}\n')
            print(f'A:Chave Privada: {Sk_A}\n')
            Pk_B, Sk_B, n_B, chave_pub_B, chave_priv_B = RSA.gerarChaves(1024)
            print(f'B:Chave Pública: {Pk_B}\n')
            print(f'B:Chave Privada: {Sk_B}\n')

            """
            A |msg|-> B
            encripta(msg, b_chave_pub)
            assina(msg, a_chave_priv)
            
            decripta(criptograma, b_chave_priv)
            verifica(msg, assinatura, a_chave_pub)
            """

            mensagem = input('Digite o texto: ')
            criptograma = RSA.encrypt(Pk_B,n_B,mensagem)

            assinatura = validador.assina(mensagem, chave_priv_A)

            texto_limpo = RSA.decrypt(Sk_B,n_B,criptograma)

            print(f'Criptograma: {criptograma}')
            print(f'Assinatura: {assinatura}')
            if texto_limpo:
                print(f'Texto Limpo: {texto_limpo}')
            else:
                print('Não foi possível decodificar')

            if validador.verifica(texto_limpo, assinatura, chave_pub_A):
                print('Assinatura verificada')
            else:
                print('Não foi possível verificar a assinatura')
        elif(op == 2):
            AES_CTR.EncryptarCTR()
        elif(op == 3):
            AES_CTR.DecryptarCTR()
        elif(op == 0):
            break
        else:
            print('\n\nOpção Inválida!\n\n')