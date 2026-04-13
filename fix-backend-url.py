

import os
import re

# Files that need BACKEND_URL fix
FILES_TO_FIX = [
    'auth.html',
    'forgot-password.html',
    'admin-forgot-password.html',
    'announcement.html',
    'payment.html',
    'admin.html',
    'dashboard.html'
]

# The new smart BACKEND_URL code
NEW_BACKEND_URL = '''const BACKEND_URL = (() => {
    const hostname = window.location.hostname;
    
    // Local development (works with mobile testing)
    if (hostname === 'localhost' || 
        hostname === '127.0.0.1' || 
        hostname.startsWith('192.168.') ||
        hostname.startsWith('10.') ||
        hostname.endsWith('.local')) {
        return `https://pg-website2.onrender.com/api`;
    }
    
    // Production - REPLACE WITH YOUR ACTUAL DOMAIN!
    // Option 1: If frontend and backend are on SAME domain
    return `${window.location.protocol}//${hostname}/api`;
    
    // Option 2: If backend is on a different domain (uncomment below)
    // return 'https://arpg-backend.onrender.com/api';
})();

console.log('✅ Using BACKEND_URL:', BACKEND_URL);'''

# Patterns to match the old BACKEND_URL
PATTERNS = [
    # Pattern 1: Standard format
    r'const BACKEND_URL\s*=\s*window\.location\.hostname\s*===\s*[\'"]localhost[\'"]\s*\?\s*[\'"]http://localhost:5000/api[\'"]\s*:\s*[\'"]https?://[^\'"]+[\'"];?',
    
    # Pattern 2: With /api at end
    r'const BACKEND_URL\s*=\s*[\'"].*?/api[\'"];?',
    
    # Pattern 3: More flexible
    r'const BACKEND_URL\s*=\s*[^;]+;'
]

def fix_file(filepath):
    """Fix BACKEND_URL in a single file"""
    
    if not os.path.exists(filepath):
        print(f'⚠️  File not found: {filepath}')
        return False
    
    print(f'🔍 Checking {filepath}...')
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Check if file already has the new code
        if 'hostname.startsWith' in content and 'endsWith(\'.local\')' in content:
            print(f'   ✅ Already fixed!')
            return True
        
        # Try to find and replace the old BACKEND_URL
        original_content = content
        replaced = False
        
        for pattern in PATTERNS:
            if re.search(pattern, content, re.DOTALL):
                content = re.sub(pattern, NEW_BACKEND_URL, content, count=1, flags=re.DOTALL)
                replaced = True
                break
        
        if not replaced:
            print(f'   ⚠️  Could not find BACKEND_URL pattern')
            return False
        
        if content == original_content:
            print(f'   ⚠️  No changes made')
            return False
        
        # Write the fixed content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        print(f'   ✅ Fixed!')
        return True
        
    except Exception as e:
        print(f'   ❌ Error: {e}')
        return False

def main():
    """Main function"""
    
    print('=' * 60)
    print('  AR PG - Automatic BACKEND_URL Fixer')
    print('=' * 60)
    print()
    
    # Change to PG directory
    pg_dir = r'd:\PG'
    
    if not os.path.exists(pg_dir):
        print(f'❌ Directory not found: {pg_dir}')
        print('Please update the pg_dir variable in the script')
        return
    
    os.chdir(pg_dir)
    print(f'📂 Working directory: {os.getcwd()}')
    print()
    
    # Fix each file
    fixed_count = 0
    failed_count = 0
    
    for filename in FILES_TO_FIX:
        if fix_file(filename):
            fixed_count += 1
        else:
            failed_count += 1
        print()
    
    # Summary
    print('=' * 60)
    print('  Summary')
    print('=' * 60)
    print(f'✅ Fixed: {fixed_count} files')
    print(f'❌ Failed: {failed_count} files')
    print()
    
    if fixed_count > 0:
        print('✅ BACKEND_URL has been updated in all files!')
        print()
        print('⚠️  IMPORTANT: After deployment, update this line in all files:')
        print('   return `${window.location.protocol}//${hostname}/api`;')
        print()
        print('   Replace with your actual backend URL if different domain:')
        print('   return \'https://arpg-backend.onrender.com/api\';')
    else:
        print('⚠️  No files were fixed. Please check manually.')
    
    print()
    print('🎉 Done!')

if __name__ == '__main__':
    main()
