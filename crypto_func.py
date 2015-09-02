# -*- coding: cp1251 -*-
__author__ = 'SuN'


SBoxCryptoProA =	((0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5),
                    (0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1),
                    (0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9),
                    (0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6),
                    (0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6),
                    (0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6),
                    (0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE),
                    (0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4))

secret_key = (1231234565,3454556778,4134545721,3636635674,3435432378,3463462564,2453322345,4232433478)

Max_4bytes_num = 4294967296L

def add_mod32(num1,num2):
    if (num1+num2)<Max_4bytes_num:
        return num1+num2
    else:
        return (num1+num2)-Max_4bytes_num

#разделяем 8 байтовое число на два 4 байтовых
def separate_data_block_8bytes(data_block_8bytes):
    N1 =  data_block_8bytes&0x00000000FFFFFFFF # младшая часть числа
    N2 =  (data_block_8bytes>>32)&0x00000000FFFFFFFF# старшая часть числа
    return (N1, N2)

def engage_two4_to_8bytes(N1,N2):
    temp = N1 | (N2<<32)
    return temp

#основной шаг криптопреобразования
def main_crypto_step(data_block_8bytes,key_chunk_4bytes):
    N1,N2 = separate_data_block_8bytes(data_block_8bytes)
    #step1
    temp1 = add_mod32(N1,key_chunk_4bytes)
    #step2
    temp2 = box_exchange(temp1)
    #step3
    temp3 = cycle_shift_11_left(temp2)
    #step4
    temp4 = temp3 ^ N2
    #step5
    N2 = N1
    N1 = temp4

    ret_val = engage_two4_to_8bytes(N1,N2)
    return ret_val

#поблочная замена
def box_exchange(figure_4bytes):
    S = [None]*8
    for i in range(8):
        S[i] = (figure_4bytes>>4*i) & 0x0000000F

    #print "%x %x %x %x %x %x %x %x "%(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7])
    for i in range(8):
       S[i]= SBoxCryptoProA[i][S[i]]

    #print "%x %x %x %x %x %x %x %x "%(S[0],S[1],S[2],S[3],S[4],S[5],S[6],S[7])
    #установка битов
    temp = 0x00000000
    for i in range(8):
        temp = temp | (S[i]<<(i*4))
    return  temp

def cycle_shift_11_left(num):
    temp1 = num<<11 #Питон безразмерен!!!
    temp2 = num>>21
    temp = ( temp1 | temp2)&0x00000000FFFFFFFF # больше 32 битных чисел у нас не будет
    #print "temp1: %X"%temp1
    #print "temp2: %X"%temp2
    #print "%X"%temp
    return temp

def crypto(data_8byte):
    for i in range(3):
        for j in range(8):
            data_8byte = main_crypto_step(data_8byte,secret_key[j])

    for j in range(8):
            data_8byte = main_crypto_step(data_8byte,secret_key[7-j])
    return data_8byte

def decrypto(data_8byte):
    for j in range(8):
            data_8byte = main_crypto_step(data_8byte,secret_key[j])

    for i in range(3):
        for j in range(8):
            data_8byte = main_crypto_step(data_8byte,secret_key[7 - j])
    return data_8byte




if __name__ =='__main__':
    data = 15446744111709551616L

    tmp = main_crypto_step(1,secret_key[0])
    tmp1 = main_crypto_step(tmp,secret_key[0])

    print tmp1
    #encr_data = crypto(data)
    #print encr_data
    #decr_data = decrypto(encr_data)
    #rint decr_data