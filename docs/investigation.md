# Authentication Failure Investigation

## Initial Detection

Windows Security Event ID 4625 indicates a failed logon.

## Key fields

- TargetUserName
- IpAddress
- WorkstationName
- LogonType
- EventID

## Investigation questions

1. Is the source IP expected?
2. Is the account valid?
3. Are failures repeated?
4. Did a successful 4624 occur afterward?
5. Is the source authorized?
6. Are other suspicious events present?

## Lab finding

The controlled event showed:

```text
EventID = 4625
TargetUserName = soclab
IpAddress = 192.168.42.3
WorkstationName = kali
LogonType = 3
```

The source was the authorized Kali VM, so the activity was benign in the lab.
