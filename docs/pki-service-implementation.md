# Conjur PKI Service Implementation Guide
## Prereq
- PKI service is up and running

## Configuration
We will have to create a `pki-admin` host. This host will have the ability to execute all Conjur PKI Service endpoints. This group is highly sensative. So make sure to manage this host within cyberark or delete this users after initial configuration.

Load the following policy to generate a `pki-admin` host and give this host admin privileges on the pki service.
```yaml
- !host pki-admin
- !grant
  role: !group pki/admin
  member: !host pki-admin
```

Load this policy on the `root` policy branch.
You should recieve something like:
```json
{
  "created_roles": {
    "cyberarkdemo:host:pki-admin": {
      "id": "cyberarkdemo:host:pki-admin",
      "api_key": "1bzwdwq2mpjpct3qtth2n2wjkh4q28qrx411rcjx9cakp5h16966jw"
    }
  },
  "version": 3
}
```
An api key will be outputted. You can onboard this host and api key into Cyberark PVWA for secure storage and management.

You can now authenticate to conjur using the outputed api key.
```bash
# Get the conjur access token and create header
access_token=$(curl https://<conjur instance>/authn/<account>/host%2Fpki-admin/authenticate --data "1bzwdwq2mpjpct3qtth2n2wjkh4q28qrx411rcjx9cakp5h16966jw" | base64)
header="Authorization: Token token=\"$access_token\""

# This should return with 'OK'
curl https://<conjur pki service>/health

# Now lets generate a self-signed certificate for the Conjur PKI Service
# self signed certificate should only be used for POCs
curl -H "$header" https://<conjur pki service>/ca/generate/selfsigned --data '{"commonName": "my-pki-service.local", "keyAlgo": "RSA", "keySize": "2048"}'




```



