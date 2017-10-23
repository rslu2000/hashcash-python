import string, random, hashlib, datetime

challenge_example = 'dJf2LKs29Djkfdj3897jfdkjf323719'

def source_generation (challenge=challenge_example, size =30):
    nonce = ''.join(random.choice(string.ascii_lowercase + string.ascii_uppercase + string.digits) for x in range(size))
    attempt = challenge + nonce
    return attempt, nonce

sha256 = hashlib.sha256()

def working():
    attempt,nonce = source_generation()
    sha256.update(attempt)
    solution = sha256.hexdigest()
    if solution.startswith('0000'):
        endtime = datetime.datetime.now()
        print solution
        print (endtime - starttime).seconds

starttime = datetime.datetime.now()

for x in range(0,1000000):
    working()


