# NetID Anonymization Tool

Provides automated anonymization for CSV-based datasets that contain common identifiers used at Illinois.  The result is an anonymized CSV with all common identifiers removed and replaced with an anonymized ID `auid`.

This script requires a project-specific secret.  Given a identifier and project-specific secret, `auid` will contain the same value.  Any difference in the identifier or secret will result in a different `auid`.


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