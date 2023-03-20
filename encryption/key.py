import string
import random

alphabet = string.ascii_letters + string.digits + '-_'
key = ''.join(random.sample(alphabet, k=32))

print(key)