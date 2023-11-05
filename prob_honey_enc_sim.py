import random as rand
import hashlib

def chain_of_opts(o_0, n_samples):
    chain = [o_0]
    hash_object = hashlib.sha256()
    i = 1
    while(i <= n_samples):
        hash_object.update(chain[i - 1].encode('utf-8'))
        hashed_data = hash_object.hexdigest()
        binary_hash = bin(int(hashed_data, 16))
        o_i = binary_hash[2:4]
        chain.append(o_i)
        i += 1
    return chain

def OTP(m, k):
    out = ''
    _len = len(m)
    if(_len != len(k)):
        return "Bit-length indescrepancy"
    i = 0
    while(i < _len):
        if((m[i] == '1' and k[i] == '1') or (m[i] == '0' and k[i] == '0')):
            out += '0'
        else:
            out += '1'
        i += 1
    return out

    
dist_keys_one = ['[0.0, 0.19]', '[0.2, 0.49]', '[0.5, 0.69]', "[0.7, 1.0]"]
dist_keys_two = ['[0.0, 0.29]', "[0.3, 0.49]", '[0.5, 0.79]', "[0.8, 1.0]"]

def inv_F(x):
    if(x == '00'):
        return [0.0, 0.19]
    elif(x == '01'):
        return [0.2, 0.49]
    elif(x == '10'):
        return [0.5, 0.69]
    else:
        return [0.7, 1.0]
    
def inv_F_dual(x):
    if(x == '00'):
        return [0.0, 0.29]
    elif(x == '01'):
        return [0.3, 0.49]
    elif(x == '10'):
        return [0.5, 0.79]
    else:
        return [0.8, 1.0]
    
def F(y):
    # 0: if 0 <= y < 0.2
    # 1: if 0.2 <= y < 0.5
    # 2: if 0.5 <= y < 0.7
    # 3: if 0.7 <= y <= 1
    if(0 <= y and y < 0.2):
        return '00'
    elif(0.2 <= y and y < 0.5):
        return '01'
    elif(0.5 <= y and y < 0.7):
        return '10'
    else:
        return '11'
    
def F_dual(y):
    # 0: if 0 <= y < 0.3
    # 1: if 0.3 <= y < 0.5
    # 2: if 0.5 <= y < 0.8
    # 3: if 0.8 <= y <= 1
    if(0 <= y and y < 0.3):
        return '00'
    elif(0.3 <= y and y < 0.5):
        return '01'
    elif(0.5 <= y and y < 0.8):
        return '10'
    else:
        return '11'

def generate_samples(N):
    i = 0
    samples = []
    while(i < N):
        r = round(rand.uniform(0.0, 1.0), 2)
        samples.append(r)
        i += 1
    return samples

def encode(messages):
    seeds = []
    for y in messages:
        r = rand.randint(0, 1)
        if(r == 0):
            seeds.append(F(y))
        else:
            seeds.append(F_dual(y))
    return seeds

def decode(seeds):
    # Decode seeds to get intervals
    intervals = []
    for x in seeds:
        r = rand.randint(0, 1)
        if(r == 0):
            intervals.append(inv_F(x))
        else:
            intervals.append(inv_F_dual(x))
    return intervals

def seed_count(seeds):
    dict = {'00' : 0, '01' : 0, '10' : 0, '11' : 0}
    for seed in seeds:
        dict[seed] += 1
    print(dict)

def interpretation_error(n_samples, actual_dist, decoy_dist):
    actual_dist = list(actual_dist.values())
    decoy_dist = list(decoy_dist.values())
    i = 0
    _len = len(actual_dist)
    total_diff = 0
    while(i < _len):
        total_diff += abs(actual_dist[i] - decoy_dist[i])
        i += 1
    error = (total_diff / n_samples) * 100
    print("Interpretation error: {}%".format(round(error, 2)))
    
def section_5_3_example(N, o_0, o_0_hat):
    samples = generate_samples(N)
    print("Actual distribution")
    seeds = encode(samples)
    seed_count(seeds)
    mess = decode(seeds)
    counters = {'[0.0, 0.19]' : 0, '[0.2, 0.49]' : 0, 
            '[0.5, 0.69]' : 0, "[0.7, 1.0]" : 0,
            '[0.0, 0.29]' : 0, "[0.3, 0.49]" : 0,
            '[0.5, 0.79]' : 0, "[0.8, 1.0]" : 0}
    for m in mess:
        counters[str(m)] += 1
    print("p_d")
    for key in dist_keys_one:
        print(key + " : " + str(counters[key]))
    print("p*_d")
    for key in dist_keys_two:
        print(key + " : " + str(counters[key]))
    actual_dist = counters

    o_chain = chain_of_opts(o_0, N)
    i = 0
    ciphertext_chain = []
    for s in seeds:
        ciphertext_chain.append(OTP(s, o_chain[i]))
        i += 1
    print()

    print("A decoy distribution (what an adversary sees)")
    seeds = []
    in_chain = chain_of_opts(o_0_hat, N)
    i = 0
    for c in ciphertext_chain:
        seeds.append(OTP(c, in_chain[i]))
        i += 1
    mess = decode(seeds)

    # Incorrectly decrypted seeds
    counters = {'[0.0, 0.19]' : 0, '[0.2, 0.49]' : 0, 
            '[0.5, 0.69]' : 0, "[0.7, 1.0]" : 0,
            '[0.0, 0.29]' : 0, "[0.3, 0.49]" : 0,
            '[0.5, 0.79]' : 0, "[0.8, 1.0]" : 0}
    for m in mess:
        counters[str(m)] += 1
    print("p_d")
    for key in dist_keys_one:
        print(key + " : " + str(counters[key]))
    print("p*_d")
    for key in dist_keys_two:
        print(key + " : " + str(counters[key]))
    decoy_dist = counters
    print()

    seeds = []
    i = 0
    print("Correct output after decoding (what a user sees)")
    for c in ciphertext_chain:
        seeds.append(OTP(c, o_chain[i]))
        i += 1
    mess = decode(seeds)

    counters = {'[0.0, 0.19]' : 0, '[0.2, 0.49]' : 0, 
            '[0.5, 0.69]' : 0, "[0.7, 1.0]" : 0,
            '[0.0, 0.29]' : 0, "[0.3, 0.49]" : 0,
            '[0.5, 0.79]' : 0, "[0.8, 1.0]" : 0}
    for m in mess:
        counters[str(m)] += 1
    print("p_d")
    for key in dist_keys_one:
        print(key + " : " + str(counters[key]))
    print("p*_d")
    for key in dist_keys_two:
        print(key + " : " + str(counters[key]))

    # Interpretation error of the Adversary
    interpretation_error(N, actual_dist, decoy_dist)
    # Interpretation error of the User
    interpretation_error(N, actual_dist, counters)

o_0 = '01' # chain of OTPs seed
o_0_hat = '00' # Adversaries guess at the seed
N = int(input("Number of messages sampled from Y: "))
section_5_3_example(N, o_0, o_0_hat)
