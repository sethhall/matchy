# Building Databases from C

Build Matchy databases from C using the builder API.

## Basic Usage

```c
#include "matchy.h"

int main() {
    // Create builder
    matchy_builder_t *builder = matchy_builder_new();
    if (!builder) {
        fprintf(stderr, "Failed to create builder\n");
        return 1;
    }
    
    // Add entries with JSON data
    matchy_builder_add(builder, "1.2.3.4", 
        "{\"threat_level\": \"high\", \"category\": \"malware\"}");
    
    // Save to file
    if (matchy_builder_save(builder, "threats.mxy") != MATCHY_SUCCESS) {
        fprintf(stderr, "Failed to save database\n");
        matchy_builder_free(builder);
        return 1;
    }
    
    // Clean up
    matchy_builder_free(builder);
    return 0;
}
```

## Adding Entries

### IP Addresses

```c
matchy_builder_add(builder, "1.2.3.4", "{\"country\": \"US\"}");
matchy_builder_add(builder, "10.0.0.0/8", "{\"type\": \"internal\"}");
```

### Glob Patterns

```c
matchy_builder_add(builder, "*.evil.com", "{\"category\": \"malware\"}");
matchy_builder_add(builder, "test[0-9].com", "{\"pattern\": \"numeric\"}");
```

### Literal Strings

```c
matchy_builder_add(builder, "exact.match.com", "{\"exact\": true}");
```

## JSON Data Format

Data must be valid JSON:

```c
// Simple object
matchy_builder_add(builder, "1.2.3.4", 
    "{\"threat_level\": \"high\"}");

// Nested object
matchy_builder_add(builder, "*.evil.com",
    "{\"threat\": {\"level\": \"critical\", \"category\": \"phishing\"}}");

// With arrays
matchy_builder_add(builder, "1.2.3.4",
    "{\"tags\": [\"malware\", \"botnet\", \"ddos\"]}");
```

## Setting Metadata

```c
matchy_builder_set_description(builder, "Daily threat intelligence database");
```

## Complete Example

```c
#include "matchy.h"
#include <stdio.h>

int main() {
    matchy_builder_t *builder = matchy_builder_new();
    if (!builder) return 1;
    
    // Set metadata
    matchy_builder_set_description(builder, "Threat Intelligence Database");
    
    // Add IP threats
    matchy_builder_add(builder, "1.2.3.4",
        "{\"threat_level\": \"high\", "
        "\"category\": \"malware\", "
        "\"confidence\": 95}");
    
    // Add domain patterns
    matchy_builder_add(builder, "*.phishing.com",
        "{\"threat_level\": \"critical\", "
        "\"category\": \"phishing\", "
        "\"tags\": [\"credential-theft\", \"active\"]}");
    
    // Save
    int result = matchy_builder_save(builder, "threats.mxy");
    matchy_builder_free(builder);
    
    if (result == MATCHY_SUCCESS) {
        printf("Database built successfully!\n");
        return 0;
    } else {
        fprintf(stderr, "Failed to build database: %d\n", result);
        return 1;
    }
}
```

## Error Handling

```c
int status = matchy_builder_add(builder, key, data);
switch (status) {
    case MATCHY_SUCCESS:
        printf("Added successfully\n");
        break;
    case MATCHY_ERROR_INVALID_PARAM:
        fprintf(stderr, "Invalid parameters\n");
        break;
    case MATCHY_ERROR_INVALID_FORMAT:
        fprintf(stderr, "Invalid JSON or key format\n");
        break;
    default:
        fprintf(stderr, "Unknown error: %d\n", status);
        break;
}
```

## See Also

- [C API Overview](c-api.md) - C API introduction
- [Querying from C](c-querying.md) - Query the built database
- [Memory Management](c-memory.md) - Memory safety
