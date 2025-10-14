#!/bin/bash
# Test GitHub Actions workflows locally before pushing

set -e

echo "🧪 GitHub Actions Workflow Testing"
echo "=================================="
echo ""

# Check if act is installed
if ! command -v act &> /dev/null; then
    echo "❌ 'act' is not installed. Install with: brew install act"
    exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker Desktop."
    exit 1
fi

echo "✓ Prerequisites checked (act + Docker)"
echo ""

# Parse command line arguments
WORKFLOW="${1:-all}"
DRY_RUN="${2:-true}"

case "$WORKFLOW" in
    ci)
        echo "📋 Testing CI workflow..."
        echo ""
        if [ "$DRY_RUN" = "true" ]; then
            echo "Dry run - listing jobs only:"
            act pull_request -l -W .github/workflows/ci.yml
        else
            echo "Running CI workflow (this will take a while)..."
            act pull_request -W .github/workflows/ci.yml
        fi
        ;;
    
    release)
        echo "📦 Testing Release workflow..."
        echo ""
        if [ "$DRY_RUN" = "true" ]; then
            echo "Dry run - listing jobs only:"
            act push -l -W .github/workflows/release.yml --eventpath <(echo '{"ref": "refs/tags/v0.5.2"}')
        else
            echo "⚠️  Warning: This will attempt to build for all platforms!"
            echo "This requires Docker images for cross-compilation and will take time."
            read -p "Continue? (y/N) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                # Test just the build-release job for current platform
                echo "Testing build-release job (macOS only)..."
                act push -W .github/workflows/release.yml --eventpath <(echo '{"ref": "refs/tags/v0.5.2"}') -j build-release --matrix os:macos-latest
            fi
        fi
        ;;
    
    docs)
        echo "📚 Testing Docs deployment workflow..."
        echo ""
        if [ "$DRY_RUN" = "true" ]; then
            echo "Dry run - listing jobs only:"
            act push -l -W .github/workflows/deploy-docs.yml
        else
            echo "Running docs build (build job only, not deploy)..."
            act push -W .github/workflows/deploy-docs.yml -j build
        fi
        ;;
    
    all)
        echo "📋 Listing all workflows and their jobs..."
        echo ""
        echo "CI Workflow:"
        act pull_request -l -W .github/workflows/ci.yml
        echo ""
        echo "Release Workflow:"
        act push -l -W .github/workflows/release.yml --eventpath <(echo '{"ref": "refs/tags/v0.5.2"}')
        echo ""
        echo "Docs Workflow:"
        act push -l -W .github/workflows/deploy-docs.yml
        echo ""
        echo "To test a specific workflow, run:"
        echo "  ./scripts/test-workflows.sh ci     # Test CI"
        echo "  ./scripts/test-workflows.sh release # Test release"
        echo "  ./scripts/test-workflows.sh docs    # Test docs"
        echo ""
        echo "Add 'run' as second argument to actually run (not just list):"
        echo "  ./scripts/test-workflows.sh ci run"
        ;;
    
    *)
        echo "❌ Unknown workflow: $WORKFLOW"
        echo ""
        echo "Usage: $0 [workflow] [run]"
        echo ""
        echo "Workflows:"
        echo "  ci       - Test CI workflow"
        echo "  release  - Test release workflow"
        echo "  docs     - Test docs workflow"
        echo "  all      - List all workflows (default)"
        echo ""
        echo "Examples:"
        echo "  $0              # List all workflows"
        echo "  $0 ci           # List CI jobs (dry run)"
        echo "  $0 ci run       # Actually run CI workflow"
        exit 1
        ;;
esac

echo ""
echo "✅ Test complete!"
