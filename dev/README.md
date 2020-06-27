# Setting up the Development Environment

To setup a running conjur instance with the correct environment variables execute the following command:
```bash
source ./setup.sh
```


Now if you execute `env` you will see the Conjur environment variables set for the pki-service.

To execute E2E tests run:
```bash
./setup-self-signed.sh
```

Since the `host/pki-service` environment variables are set, you can even execute `code .` and run the tests associated to the backend to test how PKI resources are being created and deleted from the conjur instance.
