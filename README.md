# NetID Anonymization Tool

Provides automated anonymization for CSV-based datasets that contain common identifiers.  The result is an anonymized CSV with all common identifiers removed and replaced with an anonymized ID `auid`.

This script requires a project-specific secret.  Given the same identity **and** the same secret, `auid` will contain the same value.  Any difference in the identity or secret will result in a different `auid`.  If no secret is provided, a secret is generated for you and saved as a file.

This script can be used to:
- anonymize a single dataset
- anonymize multiple separate datasets that, using the same secret, will the same identity to the same `auid`s
- anonymize a single dataset for different groups of researchers, using different secrets, to generate different `auid`s


## Usage

```
python anon-csv.py -s {project-specific secret} input-file.csv
```


## Identifiers Removed

The script removes the following common identifiers:

- `netid`
- `Last Name`
- `First Name`
- `Username`
- `Student ID`
- `UIN`