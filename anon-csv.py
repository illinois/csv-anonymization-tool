import pandas as pd
import argparse
import hashlib, binascii, base64
import sys
import time
import string
import random

#
# Argument Parsing
#
parser = argparse.ArgumentParser(description='Project specific anonymization of NetIDs.')

parser.add_argument('-s', '--secret',
  action='store', dest='secret',
  help='Project-specific secret string'
)

parser.add_argument('-S', '--secretFile',
  action='store', dest='secretFile',
  help='Project-specific secret filename'
)

parser.add_argument('inputFile', action='store')

args = parser.parse_args()
inputFile = args.inputFile

if args.secret and args.secretFile:
  sys.stderr.write(f'A single secret (-s) or secretFile (-S) must be specified, not both.\n')
  sys.exit(1)

elif not args.secret and not args.secretFile:
  # Generate a random string, from https://pythontips.com/2013/07/28/generating-a-random-string/
  def random_generator(size=6, chars=string.ascii_letters + string.digits):
    return ''.join(random.choice(chars) for x in range(size))

  secret = random_generator(32)
  timestamp  = int(round(time.time() * 1000))
  secretFile = f'secret-{timestamp}.txt'
  with open(secretFile, 'w') as f:
    f.write(secret)

  sys.stderr.write(f'== NO SECRET PROVIDED ==\n')
  sys.stderr.write(f'No secret (-s) or secretFile (-S) was provided.  A new secret was generated.\n')
  sys.stderr.write(f'- A secret is REQUIRED to create a unique, project-specific mapping of an\n' +
                   f'  identity to an anonymous identity.\n')
  sys.stderr.write(f'- You MUST provide the same secret to map the same identity to the same\n' +
                   f'  anonymous identity at a later time.  A different secret will map the\n' +
                   f'  same identity to a different anonymous identity.\n')
  sys.stderr.write(f'- Keep your secret SECURE.  The secret can be used to guess-and-check\n' +
                   f'  to uncover the identity of an anonymous identifier.\n')
  sys.stderr.write(f'\n')
  sys.stderr.write(f'Your randomly generated secret (-s) is: `{secret}`.\n')
  sys.stderr.write(f'Your secret has been saved to the file (-S): `{secretFile}`.\n')
  sys.stderr.write(f'\n')

elif args.secret:
  secret = args.secret
  
else: #args.secretFile:
  with open(args.secretFile, 'r') as f:
    secret = f.read()
  
sys.stderr.write(f'Processing `{inputFile}`...\n')


#
# Processing SALT
#
def salt_from_netid_and_secret(netid, secret):
  # Create a SHA256 hash digest of the netid:
  netid_digest = hashlib.sha256(netid).hexdigest().encode('utf-8')
  
  # Add the project-specific secret to the netid digest:
  secret = secret.encode('utf-8')
  secret = netid_digest + secret
  
  # Return a new SHA256 hash digest from the NetID digest and the secret:
  return hashlib.sha256(secret).hexdigest().encode('utf-8')


#
# Processing file
#
df = pd.read_csv(inputFile)

# Check if the file is Compass-formatted:
if "Username" in df and "netid" not in df:
  df["netid"] = df["Username"]

# Use "netid" to create anonymous_uids ("auid"):
def apply_anonymous_uids(row):
  netid = row["netid"].encode('utf-8')
  salt = salt_from_netid_and_secret(netid, secret)
  hash = hashlib.pbkdf2_hmac('sha256', netid, salt, 100000)
  auid = base64.b32encode(hash)
  auid = str(auid)[2:]
  return auid[0:2] + "-" + auid[3:8].lower() + "-" + auid[8:14].lower()

anonymous_uids = df.apply(apply_anonymous_uids, axis = 1)

# Insert "auid" as the first column:
df.insert(loc=0, column='auid', value=anonymous_uids)

# Remove columns with student identifiers column:
student_identifiers_columns = ['netid', 'Last Name', 'First Name', 'Username', 'Student ID', 'UIN']
for columnName in student_identifiers_columns:
  if columnName in df:
    sys.stderr.write(f'- Removed column `{columnName}` and data from anonymized output.\n')
    df = df.drop([columnName], axis = 1)

sys.stderr.write(f'- Processed {len(df)} row(s)\n')

# Save 
outputFile = inputFile[0:-4] + "-anonymized.csv"
df.to_csv(outputFile, index = False)

sys.stderr.write(f'- Saved anonymized file as: `{outputFile}`\n')
