# AbsoluteTimestamp

.NET library for creating and verifying RFC 3161 timestamps. Based on [Bouncy Castle](https://www.bouncycastle.org/). Available on [NuGet](https://www.nuget.org/packages/Honsdomi.AbsoluteTimestamp/).


# Basic usage
## Creating a timestamp

```cs
TimestampCreator creator = new TimestampCreator();
TimestampObject timestamp = creator
    .SetTsaPrimaryUrl("http://example.com/tsa")
    .SetDataForTimestamping("Example.pdf")
    .CreateTimestamp();
```

## Verifying a timestamp

```cs
TimestampVerifier verifier = new TimestampVerifier();
TimestampObject verifiedTimestamp = verifier
    .SetTimestampedData("Example.pdf")
    .SetTimestamp(timestamp.Timestamp)
    .Verify();
```

# API
Items highlighted in **bold** are mandatory. For further info see ITimestampCreator and ITimestampVerifier interfaces.
## Creating a timestamp
### Inputs

- **Primary TSA url** - (string)
- **Hash algorithm** - (HashAlgorithm enum value)
- **Data to be timestamped**
  - File - (byte[], stream, string)
  - List of files - (byte[][], stream[], string[])
  - Message digest(s) - (byte[], byte[][])
- **Output format** - (OutputFormat enum value)
- Secondary TSA url - (string)
- Primary and secondary TSA credentials - (string)
- TSA connection timeout - (int)
- Minimum certificate validity period - (int)

### Outputs
- Timestamp
  - TSR format
  - ASIC-S format
- Additional info (generated time, hash algorithm, signer info, ...)

## Verifying a timestamp
### Inputs

- **Timestamp** - (string, byte[], stream)
- **Hash algorithm** - (HashAlgorithm enum value)
- **Timestamped data**
  - File - (byte[], stream, string)
  - List of files - (byte[][], stream[], string[])
  - Message digest(s) - (byte[], byte[][])
- Minimum certificate validity period - (int)

### Outputs
- Timestamp
  - TSR format
  - ASIC-S format
- Additional info (generated time, hash algorithm, signer info, ...)


# Configuration file
```cs
Utils.LoadConfigurationFile("path/to/configuration/file.txt");
```
Several data, required for working with timestamps, can be provided through configuration file. Static data that doesn’t change, such as credentials to access TSA, can be retrieved from this file. This way the user doesn't have to specify these settings every time he wants to create or verify a timestamp. The configuration file is a simple text file. Each row contains exactly one key-value pair of settings separated with equals sign (example: hash.algorithm=sha1). 


| **Configuration name** | **Description** | **Value**|
|---|---|---|
|tsa.primary.url|Url address of primary TSA||
|tsa.primary.username|Username for accessing protected TSA||
|tsa.primary.password|Password for accessing protected TSA||
|tsa.secondary.url|Url address of secondary TSA||
|tsa.secondary.username|Username for accessing protected TSA||
|tsa.secondary.password|Password for accessing protected TSA||
|tsa.timeout|TSA connection timeout limit (milliseconds)||
|hash.algorithm | Hash algorithm used to create message digest|MD5/SHA1/SHA256/SHA512|
|timestamp.output | Specifies format of timestamp that is returned|TSR/ASICS|
|certificate.minimum.validity | Minimum time period when signing certificate has to be valid (days)||
