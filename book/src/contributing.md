# Contributing

Thank you for considering contributing to Matchy!

## Ways to Contribute

- **Report bugs** - File issues with reproduction steps
- **Suggest features** - Propose new capabilities
- **Fix bugs** - Submit pull requests
- **Add tests** - Improve test coverage
- **Improve docs** - Enhance documentation
- **Optimize code** - Performance improvements

## Getting Started

1. **Fork** the repository on GitHub
2. **Clone** your fork:
   ```bash
   git clone https://github.com/YOUR_USERNAME/matchy.git
   cd matchy
   ```
3. **Create** a branch:
   ```bash
   git checkout -b feature/my-feature
   ```
4. **Make** your changes
5. **Test** thoroughly:
   ```bash
   cargo test
   cargo clippy
   cargo fmt
   ```
6. **Commit** with clear messages:
   ```bash
   git commit -m "Add feature: description"
   ```
7. **Push** and create a pull request

## Development Guidelines

### Code Style

- **Run `cargo fmt`** before committing
- **Fix clippy warnings** with `cargo clippy`
- **Use descriptive names** for functions and variables
- **Add doc comments** (`///`) for public APIs
- **Keep functions focused** - one responsibility per function

### Testing

- **Write tests** for new features
- **Maintain coverage** - aim for high test coverage
- **Test edge cases** - empty inputs, large inputs, invalid data
- **Use descriptive test names** - `test_glob_matches_wildcard`

```rust
#[test]
fn test_ip_lookup_finds_exact_match() {
    let db = build_test_database();
    let result = db.lookup("1.2.3.4").unwrap();
    assert!(result.is_some());
}
```

### Documentation

- **Document public APIs** with `///` comments
- **Include examples** in doc comments
- **Update mdBook docs** for user-facing changes
- **Keep README current**

```rust
/// Lookup an entry in the database
///
/// # Examples
///
/// ```
/// let db = Database::open("db.mxy")?;
/// let result = db.lookup("1.2.3.4")?;
/// ```
pub fn lookup(&self, query: &str) -> Result<Option<QueryResult>> {
    // ...
}
```

### Commit Messages

Use clear, descriptive commit messages:

```
Add: Brief description of what was added
Fix: Brief description of what was fixed
Docs: Brief description of documentation changes
Test: Brief description of test changes
Perf: Brief description of performance improvements
```

## Pull Request Process

1. **Update tests** - Add/update tests for your changes
2. **Update docs** - Update relevant documentation
3. **Run CI checks** locally:
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt -- --check
   ```
4. **Write clear PR description** - Explain what and why
5. **Link related issues** - Reference any related issues
6. **Be responsive** - Address review feedback promptly

## Code of Conduct

- **Be respectful** - Treat everyone with respect
- **Be constructive** - Provide helpful feedback
- **Be patient** - Maintainers are often volunteers
- **Be collaborative** - Work together towards solutions

## Questions?

Feel free to:
- **Open an issue** for questions
- **Start a discussion** for brainstorming
- **Check existing docs** for answers

Thank you for contributing! 🎉
