# -*- coding: utf-8 -*-

"""
Symbols and Operations
    The following symbols are used in the secure hash algorithm specifications; each operates on w-bit words:

    ∧ Bitwise AND operation.
    ∨ Bitwise OR (“inclusive-OR”) operation.
    ⊕ Bitwise XOR (“exclusive-OR”) operation.
    ¬ Bitwise complement operation.
    + Addition modulo 2w.
    << Left-shift operation, where x << n is obtained by discarding the left-most n bits of the word x
        and then padding the result with n zeroes on the right.
    >> Right-shift operation, where x >> n is obtained by discarding the rightmost n bits of the word x
        and then padding the result with n zeroes on the left.
"""


BLOCK_SIZE = 64
DIGEST_SIZE = 32
BITS_IN_WORD = 32  # w - Number of bits in a word.

# SHA-224 and SHA-256 use the same sequence of sixty-four constant 32-bit words.These words represent
# the first thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers.
K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Before hash computation begins for each of the secure hash algorithms, the initial hash value,
# H(0), must be set. The size and number of words in H(0) depends on the message digest size.
# For SHA-256, the initial hash value, H(0), shall consist of the following eight 32-bit words, in hex:
INITIAL_HASH = [0x6A09E667, 0xBB67AE85, 0x3C6EF372,
                0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


def shift_right(x, n):
    """The right shift operation SHR n(x), where x is a w-bit word and n is an integer with 0 ≤ n < w, is defined by
    SHR n (x)=x >> n.
    """
    return (x & 0xffffffff) >> n


def rotate_right(x, y):
    """The rotate right (circular right shift) operation, where x is a w-bit word
    and n is an integer with 0 ≤ n < w, is defined by ROTR n (x) =(x >> n) ∨ (x << w - n).
    """
    return (((x & 0xffffffff) >> (y & 31)) | (x << (BITS_IN_WORD - (y & 31)))) & 0xffffffff


"""
SHA256 uses six logical functions, where each function operates on 64-bit words,
which are represented as x, y, and z. The result of each function is a new 64-bit word.
"""


def choose(x, y, z):
    """The x input chooses if the output is from y or z.

    Ch(x,y,z)=(x∧y)⊕(¬x∧z)
    """
    return z ^ (x & (y ^ z))


def majority(x, y, z):
    """The result is set according to the majority of the 3 inputs.

    Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)

    The functions are defined for bit vectors (of 32 bits in case fo SHA-256)
    """
    return ((x | y) & z) | (x & y)


def sigma0(x):
    # ROTR 2(x) ⊕ ROTR 13(x) ⊕ ROTR 22(x)
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)


def sigma1(x):
    # ROTR 6(x) ⊕ ROTR 11(x) ⊕ ROTR 25(x)
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)


def gamma0(x):
    # ROTR 7(x) ⊕ ROTR 18(x) ⊕ SHR 3(x)
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)


def gamma1(x):
    # ROTR 17(x) ⊕ ROTR 19(x) ⊕ SHR 10(x)
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)


def deMutate(digest):
    # for x,y in enumerate(digest):
    # print(x)
    # print(y)
    return 0


def mutate(data, digest):

    original_digest_copy = digest[:]

    # 6.2.2:  The SHA-256 hash computation uses functions and constants previously
    # defined in Sec. 4.1.2 and Sec. 4.2.2, respectively.
    # Addition (+) is performed modulo 232.

    # Prepare the message schedule, {Wt}:
    print("DATA")
    print(data)

    original_digest_copy = mixValuesIntoHashCopy(original_digest_copy, data)

    returnList = list()
    for idx, x in enumerate(digest):
        print
        appendingValue = (x + original_digest_copy[idx]) & 0xffffffff
        returnList.append(appendingValue)
        print(idx)
        print(bin(0xffffffff))
        print(bin(x + original_digest_copy[idx]))
        print(bin(appendingValue))

    return returnList
    # return [(x + digest_copy[idx]) & 0xffffffff for idx, x in enumerate(digest)]


def get_buffer(s):
    if isinstance(s, str):
        return s
    if isinstance(s, str):
        try:
            return str(s)
        except UnicodeEncodeError:
            pass
    return memoryview(s)

def deMixValuesFromHashCopy(mixedShaCopy):
    print("HOLY SHIT")
    # w = []
    # for i in range(0, 16):
    #     w.append(sum([
    #         data[4 * i + 0] << 24,
    #         data[4 * i + 1] << 16,
    #         data[4 * i + 2] << 8,
    #         data[4 * i + 3] << 0,
    #     ]))
    # for i in range(16, 64):
    #     sum_ = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
    #     w.append(sum_ & 0xffffffff)

def mixValuesIntoHashCopy(hashListCopy, data):
    w = []
    for i in range(0, 16):
        w.append(sum([
            data[4 * i + 0] << 24,
            data[4 * i + 1] << 16,
            data[4 * i + 2] << 8,
            data[4 * i + 3] << 0,
        ]))
    for i in range(16, 64):
        sum_ = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
        w.append(sum_ & 0xffffffff)

    for idx in range(0, -64, -1):
        i = abs(idx % 8)
        print("INDEXX")
        print(idx)
        # Initialize the eight working variables, a, b, c, d, e, f, g, and h  with the (i-1)st hash value.
        # W is the prepared message schedule.
        positions = [(i + x) % 8 for x in range(8)]
        print("POSITIONS")
        print(positions)
        d_position = positions[3]
        h_position = positions[-1]
        a, b, c, d, e, f, g, h = [hashListCopy[pos] for pos in positions]
        print("HMM")
        print(idx)
        print(w[abs(idx)])
        t1 = h + sigma1(e) + choose(e, f, g) + K256[abs(idx)] + w[abs(idx)]
        t2 = sigma0(a) + majority(a, b, c)
        hashListCopy[d_position] = (d + t1) & 0xffffffff
        hashListCopy[h_position] = (t1 + t2) & 0xffffffff
    return hashListCopy


def zeros(count):
    returnValue = [0] * count
    return returnValue

# 2447ae19112009c0d536cb90fe8bca9af5d629075d5e7c31283377b119d9b952 -- correct value of omfg


class SHA256(object):
    def __init__(self, string=None):
        self._sha = {
            'digest': INITIAL_HASH,
            'count_lo': 0,
            'count_hi': 0,
            'data': zeros(BLOCK_SIZE),
        }
        if not string:
            return
        buff = get_buffer(string)
        # BUFFER IS JUST THE STRING
        # print("BUFF")
        # print(buff)
        count = len(buff)
        count_lo = (self._sha['count_lo'] + (count << 3)) & 0xffffffff
        # Count is just the count
        # print("COUNT LO")
        # print(count_lo)
        if count_lo < self._sha['count_lo']:
            self._sha['count_hi'] += 1
        self._sha['count_lo'] = count_lo
        self._sha['count_hi'] += (count >> 29)

        print("BEFORE INITIALIZING LOOP")
        buffer_idx = 0
        while count >= BLOCK_SIZE:
            print("WITHIN INITIALIZING LOOP")
            self._sha['data'] = [
                ord(c) for c in buff[buffer_idx:buffer_idx + BLOCK_SIZE]]
            count -= BLOCK_SIZE
            buffer_idx += BLOCK_SIZE
            self._sha['digest'] = mutate(
                self._sha['data'], self._sha['digest'])

        print("AFTER INITIALIZING LOOP")
        print(self._sha['digest'])
        self._sha['data'][:count] = [
            ord(c) for c in buff[buffer_idx:buffer_idx + count]]

    def hexdigest(self):
        """
        A hex digit is an element of the set {0, 1,…, 9, a,…, f}.
        A hex digit is the representation of a 4-bit string. For example, the hex digit “7” represents
        the 4-bit string “0111”, and the hex digit “a” represents the 4-bit string “1010”.
        """
        hash = self._sha.copy()
        print("ORIGINAL HASH")
        print(hash['data'])
        print(hash['digest'])
        count = (hash['count_lo'] >> 3) & 0x3f
        print("COUNT LO")
        print(count)
        hash['data'][count] = 0x80
        print("DATA")
        print(hash['data'])

        count += 1
        if count > BLOCK_SIZE - 8:
            # fill with zero bytes after the count
            hash['data'] = hash['data'][:count] + zeros(BLOCK_SIZE - count)
            hash['digest'] = mutate(hash['data'], hash['digest'])
            # fill with zero bytes
            hash['data'] = [0] * BLOCK_SIZE
        else:
            hash['data'] = hash['data'][:count] + zeros(BLOCK_SIZE - count)

        print("FINAL HASH DATA BEFORE LOOP")
        print(hash['data'])

        for idx, shift in zip(range(56, 64), range(24, -1, -8) * 2):
            print("HASH COUNT HI")
            hash['data'][idx] = (
                hash['count_hi' if idx < 60 else 'count_lo'] >> shift) & 0xff
            print(hash['count_hi'])
            print(hash['count_lo'])
            print(str(idx < 60))
            print("NEW HASH AT INDEX #" + str(idx))
            print(hash['data'])
            print(0xffffffff)

        hash['digest'] = mutate(hash['data'], hash['digest'])
        # EVERYTHING AFTER THIS POINT SOLVED

        digest = []

        for i in hash['digest']:

            values = []
            for shift in range(24, -1, -8):

                appendingValue = (i >> shift) & 0xff
                digest.append(appendingValue)
                values.append(bin(appendingValue))

        returnValue = ''.join([('%.2x' % i) for i in digest])
        print("\n\nRETURN VALUE")
        print(returnValue)
        return returnValue


def shaString():
    print("HASHING inputSTR")
    inputStr = 'omfg'
    output = SHA256(inputStr).hexdigest()
    print("OUTPUT")
    print(output)
    deSHA(output)


def deSHA(sha):
    print("FIRST BACK TO LIST OF NUMBERS")
    fullListOfNumbers = SHAStringToList(sha)
    groupedNumbers = groupSHANumbers(fullListOfNumbers)
    hashedNumbers = getHASHValues(groupedNumbers)
    deMutated = deMutate(hashedNumbers)
    print(deMutated)


def getHASHValues(allValues):
    hashValues = list()
    for valueSet in allValues:
        index = 0
        valuesToAdd = []
        for shift in range(24, -1, -8):
            valuesToAdd.append((valueSet[index] << shift) & 0xffffffff)
            index += 1
        hashValues.append(sum(valuesToAdd))

    return hashValues
    # for i in hash['digest']:
    #         print(i)
    #         for shift in range(24, -1, -8):
    #             appendingValue = (i >> shift) & 0xff
    #             digest.append(appendingValue)


def groupSHANumbers(listOfUngroupedNumbers):
    print(listOfUngroupedNumbers)
    groupedNumbers = [[0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [
        0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0], [0, 0, 0, 0]]
    # [[0]*4]*int(len(listOfUngroupedNumbers)/4)
    index = 0
    # print(groupedNumbers)
    for i in range(len(listOfUngroupedNumbers)/4):
        #print("AT INDEX")
        # print(i)
        for j in range(4):
            # print(listOfUngroupedNumbers[index])
            # print(i)
            groupedNumbers[i][j] = (listOfUngroupedNumbers[index])
            # print(groupedNumbers)
            index += 1

    return groupedNumbers


def SHAStringToList(sha):
    listOfChars = list(sha)
    groupedChars = list()
    for i in range(len(listOfChars)):
        if i % 2 == 0:
            # print("EVEN")
            groupedChars.append(str(listOfChars[i])+str(listOfChars[i+1]))

    # print("GROUPED CHARS")

    # print(groupedChars)
    numbersFromChars = map(SHAStrToInt, groupedChars)

    return numbersFromChars


def SHAStrToInt(s):
    return int(s, base=16)


def test():
    string = 'Lorem ipsum dolor sit amet, consectetur adipiscing elit.'
    assert 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' == SHA256().hexdigest()
    assert 'a58dd8680234c1f8cc2ef2b325a43733605a7f16f288e072de8eae81fd8d6433' == SHA256(
        string).hexdigest()
    assert 'db7b94909697ac91e9f167159b99a1d2612b5cf4b3086a72cb6ac0206c4bd47c' == SHA256(
        string * 7).hexdigest()
    assert '1aa4458852eefd69560827a035db9df11491abdae3483a71d1707f05e085e682' == SHA256(
        'hello⊕').hexdigest()
    long_text = string * 999
    assert '5e4e5fcc4c89b7b1b6567d81187e83c99cd7c04ca77a093ed74e35a08046d519' == SHA256(
        long_text).hexdigest()
    assert 'c7ae9b6438e9dfccfd486fabed3c08d6f63ae559ef09b2fe084a38dbc46fae7c' == SHA256(
        u'\uE52D').hexdigest()
    print('ok')


# if __name__ == "__main__":
#     test()
if __name__ == "__main__":
    shaString()
    # test()
