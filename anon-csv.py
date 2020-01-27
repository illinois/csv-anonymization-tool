import pandas as pd
import argparse
import hashlib, binascii, base64
import sys

#
# Argument Parsing
#
parser = argparse.ArgumentParser(description='Project specific anonymization of NetIDs.')

parser.add_argument('-s', '--secret',
  action='store', dest='secret', required=True,
  help='Project-specific feature (required)'
)

parser.add_argument('inputFile', action='store')

args = parser.parse_args()
inputFile = args.inputFile
secret = args.secret

sys.stderr.write(f'Processing "{inputFile}"...\n')
sys.stderr.write(f'- Using project-specific secret: "{secret}"\n')


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
