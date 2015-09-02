# -*- coding: cp1251 -*-
__author__ = 'SuN'
import pdb


SBoxCryptoProA =	((0x9,0x6,0x3,0x2,0x8,0xB,0x1,0x7,0xA,0x4,0xE,0xF,0xC,0x0,0xD,0x5),
                    (0x3,0x7,0xE,0x9,0x8,0xA,0xF,0x0,0x5,0x2,0x6,0xC,0xB,0x4,0xD,0x1),
                    (0xE,0x4,0x6,0x2,0xB,0x3,0xD,0x8,0xC,0xF,0x5,0xA,0x0,0x7,0x1,0x9),
                    (0xE,0x7,0xA,0xC,0xD,0x1,0x3,0x9,0x0,0x2,0xB,0x4,0xF,0x8,0x5,0x6),
                    (0xB,0x5,0x1,0x9,0x8,0xD,0xF,0x0,0xE,0x4,0x2,0x3,0xC,0x7,0xA,0x6),
                    (0x3,0xA,0xD,0xC,0x1,0x2,0x0,0xB,0x7,0x5,0x9,0x4,0x8,0xF,0xE,0x6),
                    (0x1,0xD,0x2,0x9,0x7,0xA,0x6,0x0,0x8,0xC,0x4,0x5,0xF,0x3,0xB,0xE),
                    (0xB,0xA,0xF,0x5,0x0,0xC,0xE,0x8,0x6,0x2,0x3,0x9,0x1,0x7,0xD,0x4))

secret_key = (1231234565,3454556778,4134545721,3636635674,3435432378,3463462564,2453322345,4232433478)

Max_4bytes_num = 4294967295L

def add_mod32(num1,num2):
    if (num1+num2) < Max_4bytes_num:
        return num1+num2
    else:
        return ((num1+num2)-Max_4bytes_num)

def test_add_mod32():
    a = 0xFAFFDDBB
    b = 0x43FFCCAA
    out = 0x3EFFAA66
    temp = add_mod32(a,b)
    if temp == out:
        print 'test success'
    else:
        print 'test fail'

#разделяем 8 байтовое число на два 4 байтовых
def separate_data_block_8bytes(data_block_8bytes):
    N1 =  data_block_8bytes&0x00000000FFFFFFFF # младшая часть числа
    N2 =  (data_block_8bytes>>32)&0x00000000FFFFFFFF# старшая часть числа
    return (N1, N2)

def test_separate_data_block_8bytes():
    test_num = 0xABCD1234FEDCBA11
    N1,N2 = separate_data_block_8bytes(test_num)
    if N1 == 0xFEDCBA11 and N2 == 0xABCD1234:
        print 'test success'
    else:
        print 'test fail'

def engage_two4_to_8bytes(N1,N2):
    temp = N1 | (N2<<32)
    return temp

def test_engage_two4_to_8bytes():
    a = 0xABABABAB
    b = 0xCDCDCDCD
    out = 0xCDCDCDCDABABABAB
    ret = engage_two4_to_8bytes(a,b)
    if ret == out:
        print "test success"
    else:
        print "test fail"


#основной шаг криптопреобразования
def main_crypto_step(data_block_8bytes,key_chunk_4bytes):
    #step0
    N1,N2 = separate_data_block_8bytes(data_block_8bytes)
    #step1
    temp1 = add_mod32(N1,key_chunk_4bytes)
    #step2
    temp2 = box_exchange(temp1) #good
    #step3
    temp3 = cycle_shift_11_left(temp2) #good
    #step4
    temp4 = temp3 ^ N2 #good
    #step5
    N2 = N1     #good
    N1 = temp4
    #step6
    ret_val = engage_two4_to_8bytes(N1,N2)
    return ret_val

#поблочная замена
def box_exchange(figure_4bytes):
    #pdb.set_trace()
    S = [None]*8
    temp = 0x00000000L
    for i in range(8):
        S[i] = int((figure_4bytes>>4*i) & 0x0000000F)
        S[i]= SBoxCryptoProA[i][S[i]]
        temp|=(S[i]<<(i*4))

    return  temp

def test_box_exchange():
    #pdb.set_trace()
    num = 0x01234567
    out = 0xBDD9D3F7
    ret = box_exchange(num)
    if out == ret:
        print 'test success'
    else:
        print 'test fail'

def cycle_shift_11_left(num):
    temp1 = ((num<<11) & 0x00000000FFFFFFFF)#Питон безразмерен!!!
    temp2 = (num>>21)
    temp = ( temp1 | temp2)  # больше 32 битных чисел у нас не будет
    return temp

def test_cycle_shift_11_left():
    num  = 0x11223344
    out  = 0x119A2089
    ret = cycle_shift_11_left(num)
    if out == ret:
        print 'test success'
    else:
        print 'test fail'

def crypto(data_8byte):
    counter = 0
    for i in range(3):
        for j in range(8):
            data_8byte = main_crypto_step(data_8byte,secret_key[j])
            counter+=1

    for j in range(8):
        data_8byte = main_crypto_step(data_8byte,secret_key[7-j])
        counter+=1

    print "counter encr = %d"%counter
    return data_8byte

def decrypto(data_8byte):
    counter = 0
    for j in range(8):
        data_8byte = main_crypto_step(data_8byte,secret_key[j])
        counter+=1

    for i in range(3):
        for j in range(8):
            data_8byte = main_crypto_step(data_8byte,secret_key[7 - j])
            counter+=1
    print "counter decr = %d"%counter
    return data_8byte


def test_app():
    if test_separate_data_block_8bytes():
        return True



if __name__ =='__main__':
    data = 0xDAAAAAAABBBBBBBD

    print 'before crypt: %X'%data
    crypted  = crypto(data)
    print 'after crypt : %X'%crypted
    decrypted = decrypto(crypted)
    print 'decrypted   : %X'%decrypted
    test_separate_data_block_8bytes()   #0
    test_add_mod32()                    #1
    test_box_exchange()                 #2
    test_cycle_shift_11_left()          #3
                                        #4 no matter
                                        #5 no matter
    test_engage_two4_to_8bytes()        #6

    num = 0x12345656
    for i in range(32):
        num = cycle_shift_11_left(num)
        print '%X'%num

