import os
import csv
import zipfile
from pathlib import Path
from collections import defaultdict
import re
import json
from datetime import datetime

def get_user_inputs():
    """Interactive prompts for user inputs"""
    print("=== Database Field Aggregator - Enhanced Version ===")
    print("Comprehensive aggregation with advanced analytics and detailed usage tracking")
    print()
    
    # Get input directory
    while True:
        directory = input("Enter the directory path containing the zip/tflx folders: ").strip()
        if os.path.exists(directory):
            break
        print(f"Error: Directory '{directory}' does not exist. Please try again.")
    
    # Get output file
    output_file = input("Enter the name for the output CSV file (without extension): ").strip()
    if not output_file.lower().endswith('.csv'):
        output_file += '.csv'
    
    # Database filtering options
    print("\nDatabase filtering options:")
    print("1. All databases (Oracle, SQL Server, PostgreSQL, MySQL, etc.)")
    print("2. Oracle only")
    print("3. SQL Server only") 
    print("4. PostgreSQL only")
    print("5. MySQL only")
    
    while True:
        choice = input("Enter your choice (1-5): ").strip()
        filter_map = {
            '1': None,
            '2': 'Oracle',
            '3': 'SQL Server',
            '4': 'PostgreSQL', 
            '5': 'MySQL'
        }
        if choice in filter_map:
            filter_database_type = filter_map[choice]
            break
        print("Invalid choice. Please enter 1-5.")
    
    # Analysis depth options
    print("\nAnalysis depth options:")
    print("1. Standard aggregation")
    print("2. Deep analysis (includes usage patterns and transformation tracking)")
    
    while True:
        depth_choice = input("Enter your choice (1-2): ").strip()
        if depth_choice in ['1', '2']:
            deep_analysis = depth_choice == '2'
            break
        print("Invalid choice. Please enter 1 or 2.")
    
    return directory, output_file, filter_database_type, deep_analysis

def is_database_source_enhanced(data_source):
    """Enhanced check if a data source is a database connection"""
    if not data_source or data_source == 'Unknown':
        return False
    
    # Exclude file-based sources
    file_indicators = [
        'File:', 'CSV/Text File:', 'Excel File:', 'JSON File:', 
        'file://', 'C:\\', 'D:\\', '/home/', '/var/', '/tmp/',
        '.csv', '.xlsx', '.xls', '.txt', '.json'
    ]
    if any(indicator in data_source for indicator in file_indicators):
        return False
    
    # Include database indicators
    database_indicators = [
        'Oracle:', 'SQL Server:', 'PostgreSQL:', 'MySQL:', 'Database:',
        'Teradata:', 'Snowflake:', 'Redshift:', 'BigQuery:', 'Databricks:',
        'Sybase:', 'DB2:', 'Informix:', 'Access:', 'SQLite:'
    ]
    
    if any(indicator in data_source for indicator in database_indicators):
        return True
    
    # Check for server.schema.table pattern (likely database)
    if re.match(r'^[^:]+\.[^:]+\.[^:]+$', data_source.strip()):
        return True
    
    # Check for connection string patterns
    connection_patterns = [
        r'jdbc:', r'odbc:', r'server=', r'host=', r'port=\d+',
        r'\d+\.\d+\.\d+\.\d+', r'localhost:', r'database='
    ]
    if any(re.search(pattern, data_source, re.IGNORECASE) for pattern in connection_patterns):
        return True
    
    # Include Tableau Server sources (often database-backed)
    if 'Tableau Server:' in data_source:
        return True
    
    return False

def get_enhanced_database_type(data_source):
    """Enhanced database type detection with comprehensive patterns"""
    if not data_source:
        return 'Unknown'
    
    data_source_lower = data_source.lower()
    
    # Direct prefix-based detection
    prefix_mappings = {
        'Oracle:': 'Oracle',
        'SQL Server:': 'SQL Server',
        'PostgreSQL:': 'PostgreSQL',
        'MySQL:': 'MySQL',
        'Teradata:': 'Teradata',
        'Snowflake:': 'Snowflake',
        'Redshift:': 'Redshift',
        'BigQuery:': 'BigQuery',
        'Databricks:': 'Databricks',
        'Sybase:': 'Sybase',
        'DB2:': 'DB2',
        'Informix:': 'Informix',
        'Access:': 'Access',
        'SQLite:': 'SQLite',
        'Database:': 'Database',
        'Tableau Server:': 'Tableau Server'
    }
    
    for prefix, db_type in prefix_mappings.items():
        if data_source.startswith(prefix):
            return db_type
    
    # Enhanced pattern-based detection
    db_patterns = {
        'Oracle': [
            'oracle', 'ora_', 'orcl', 'xe', 'sid=', 'ora12', 'ora19', 'ora21',
            'oracle.jdbc', 'oracledriver', '@(description='
        ],
        'SQL Server': [
            'sqlserver', 'mssql', 'microsoft', 'tsql', '.dbo.', 'sql server',
            'sqlexpress', 'sqlcmd', 'trusted_connection', 'integrated security'
        ],
        'PostgreSQL': [
            'postgres', 'postgresql', 'psql', 'pg_', 'pgsql',
            'postgresql.jdbc', 'postgresdriver'
        ],
        'MySQL': [
            'mysql', 'mariadb', 'my_', 'mysql.jdbc', 'mysqldriver',
            'maria', 'percona'
        ],
        'Teradata': [
            'teradata', 'td_', 'tera', 'teradata.jdbc', 'teradatadriver'
        ],
        'Snowflake': [
            'snowflake', 'snow_', 'snowflakecomputing', 'snowflake.jdbc'
        ],
        'Redshift': [
            'redshift', 'rs_', 'redshift.amazonaws', 'redshift.jdbc'
        ],
        'BigQuery': [
            'bigquery', 'bq_', 'googleapis', 'bigquery.googleapis'
        ],
        'Databricks': [
            'databricks', 'spark', 'delta', 'databricks.jdbc'
        ],
        'Sybase': [
            'sybase', 'ase', 'sybase.jdbc', 'sybasedriver'
        ],
        'DB2': [
            'db2', 'ibm', 'db2.jdbc', 'db2driver'
        ]
    }
    
    for db_type, patterns in db_patterns.items():
        if any(pattern in data_source_lower for pattern in patterns):
            return db_type
    
    return 'Other'

def parse_enhanced_data_source(data_source):
    """Enhanced data source parsing with comprehensive component extraction"""
    components = {
        'server': 'Unknown',
        'database': 'Unknown',
        'schema': 'Unknown', 
        'table': 'Unknown',
        'port': '',
        'full_name': data_source,
        'connection_type': 'Unknown'
    }
    
    # Handle prefixed data sources
    if ':' in data_source:
        prefix, connection_string = data_source.split(':', 1)
        components['connection_type'] = prefix.strip()
        connection_string = connection_string.strip()
    else:
        connection_string = data_source
    
    # Parse different connection string formats
    
    # Format 1: server.database.schema.table
    if connection_string.count('.') >= 3:
        parts = connection_string.split('.')
        components['server'] = parts[0].strip()
        components['database'] = parts[1].strip()
        components['schema'] = parts[2].strip()
        components['table'] = parts[3].strip('[]"`')
    
    # Format 2: server.schema.table
    elif connection_string.count('.') == 2:
        parts = connection_string.split('.')
        components['server'] = parts[0].strip()
        components['schema'] = parts[1].strip()
        components['table'] = parts[2].strip('[]"`')
    
    # Format 3: schema.table
    elif connection_string.count('.') == 1:
        parts = connection_string.split('.')
        components['schema'] = parts[0].strip()
        components['table'] = parts[1].strip('[]"`')
    
    # Format 4: Single table name
    elif '.' not in connection_string:
        components['table'] = connection_string.strip('[]"`')
    
    # Extract port if present
    server_part = components['server']
    if ':' in server_part:
        server, port = server_part.split(':', 1)
        components['server'] = server
        components['port'] = port
    
    return components

def resolve_unknown_table_name_enhanced(data_source, parent_folder, table_mappings, file_context):
    """Enhanced table name resolution with multiple strategies and context"""
    if 'Unknown' not in data_source:
        return data_source
    
    print(f"    🔍 Enhanced resolution for 'Unknown' table in: {data_source}")
    
    # Strategy 1: Check existing mappings from this run
    if parent_folder in table_mappings:
        for mapping in table_mappings[parent_folder]:
            if 'Unknown' in mapping['original']:
                resolved = data_source.replace('Unknown', mapping['resolved'])
                print(f"    ✅ Resolved using cached mapping: {resolved}")
                return resolved
    
    # Strategy 2: Analyze file context for table hints
    if file_context and 'csv_files' in file_context:
        for csv_file in file_context['csv_files']:
            # Look for table names in CSV file names
            csv_lower = csv_file.lower()
            table_hints = []
            
            # Extract potential table names from file paths
            if 'input_fields' in csv_lower:
                # Look for patterns like "input_fields_TableName.csv"
                match = re.search(r'input_fields_([^_]+)\.csv', csv_lower)
                if match:
                    table_hints.append(match.group(1))
            
            # Look for transformation file patterns
            if 'transformations' in csv_lower:
                match = re.search(r'transformations_([^_]+)\.csv', csv_lower)
                if match:
                    table_hints.append(match.group(1))
            
            # Use the first valid hint found
            for hint in table_hints:
                if hint and len(hint) > 2:  # Reasonable table name length
                    resolved_source = data_source.replace('Unknown', hint)
                    
                    # Store this resolution
                    if parent_folder not in table_mappings:
                        table_mappings[parent_folder] = []
                    table_mappings[parent_folder].append({
                        'original': data_source,
                        'resolved': hint,
                        'method': 'file_context'
                    })
                    
                    print(f"    ✅ Resolved using file context: {resolved_source}")
                    return resolved_source
    
    # Strategy 3: Enhanced pattern matching in folder names
    folder_lower = parent_folder.lower()
    
    enhanced_table_patterns = [
        r'(\w+_table)',
        r'(\w+_data)',
        r'(fact_\w+)',
        r'(dim_\w+)',
        r'(\w+_master)',
        r'(\w+_staging)',
        r'(\w+_temp)',
        r'(src_\w+)',
        r'(tgt_\w+)',
        r'(\w+_view)',
        r'(\w+_summary)',
        r'(ref_\w+)',
        r'(\w+_lookup)',
        r'(\w+_bridge)',
        r'(etl_\w+)',
        r'(\w+_history)',
        r'(\w+_snapshot)',
        r'(raw_\w+)',
        r'(clean_\w+)'
    ]
    
    for pattern in enhanced_table_patterns:
        match = re.search(pattern, folder_lower)
        if match:
            potential_table = match.group(1)
            resolved_source = data_source.replace('Unknown', potential_table)
            
            # Store this resolution
            if parent_folder not in table_mappings:
                table_mappings[parent_folder] = []
            table_mappings[parent_folder].append({
                'original': data_source,
                'resolved': potential_table,
                'method': 'pattern_matching'
            })
            
            print(f"    ✅ Resolved using enhanced pattern: {resolved_source}")
            return resolved_source
    
    # Strategy 4: Use flow name if it contains table-like patterns
    flow_name_patterns = [
        r'([A-Z][a-z]+(?:[A-Z][a-z]+)*)',  # CamelCase
        r'([a-z]+(?:_[a-z]+)*)',          # snake_case
        r'([A-Z]+(?:_[A-Z]+)*)'           # UPPER_CASE
    ]
    
    for pattern in flow_name_patterns:
        matches = re.findall(pattern, parent_folder)
        for match in matches:
            if len(match) >= 4 and not any(word in match.lower() for word in ['flow', 'prep', 'tableau', 'analysis']):
                resolved_source = data_source.replace('Unknown', match)
                
                # Store this resolution
                if parent_folder not in table_mappings:
                    table_mappings[parent_folder] = []
                table_mappings[parent_folder].append({
                    'original': data_source,
                    'resolved': match,
                    'method': 'flow_name'
                })
                
                print(f"    ✅ Resolved using flow name pattern: {resolved_source}")
                return resolved_source
    
    # Strategy 5: Fallback to cleaned folder name
    clean_folder = re.sub(r'[^a-zA-Z0-9_]', '_', parent_folder)
    clean_folder = re.sub(r'_+', '_', clean_folder).strip('_')
    
    if clean_folder and len(clean_folder) >= 3:
        resolved_source = data_source.replace('Unknown', clean_folder)
        
        # Store this resolution
        if parent_folder not in table_mappings:
            table_mappings[parent_folder] = []
        table_mappings[parent_folder].append({
            'original': data_source,
            'resolved': clean_folder,
            'method': 'fallback_cleanup'
        })
        
        print(f"    ✅ Resolved using fallback cleanup: {resolved_source}")
        return resolved_source
    
    print(f"    ❌ Could not resolve: {data_source}")
    return data_source

def extract_usage_patterns_enhanced(row, deep_analysis):
    """Extract detailed usage patterns from row data with enhanced categorization"""
    usage_patterns = {
        'transformations': [],
        'calculations': [],
        'joins': [],
        'aggregations': [],
        'filters': [],
        'unions': [],
        'pivots': [],
        'renames': [],
        'outputs': []
    }
    
    if not deep_analysis:
        return usage_patterns
    
    # Analyze multiple columns for usage patterns
    analysis_columns = [
        row.get('Usage Reason', ''),
        row.get('Usage Reasons', ''),
        row.get('Transformation Summary', ''),
        row.get('Details', ''),
        row.get('Formula', ''),
        row.get('Context', '')
    ]
    
    for text in analysis_columns:
        if not text:
            continue
        
        text_lower = text.lower()
        
        # Pattern matching for different transformation types
        if any(calc_word in text_lower for calc_word in ['calculation', 'formula', 'expression', 'computed']):
            usage_patterns['calculations'].append(text)
        
        if any(join_word in text_lower for join_word in ['join', 'inner', 'left', 'right', 'outer', 'cross']):
            usage_patterns['joins'].append(text)
        
        if any(agg_word in text_lower for agg_word in ['group', 'aggregate', 'sum', 'count', 'avg', 'max', 'min']):
            usage_patterns['aggregations'].append(text)
        
        if any(filter_word in text_lower for filter_word in ['filter', 'where', 'condition', 'criteria']):
            usage_patterns['filters'].append(text)
        
        if any(union_word in text_lower for union_word in ['union', 'append', 'combine']):
            usage_patterns['unions'].append(text)
        
        if any(pivot_word in text_lower for pivot_word in ['pivot', 'unpivot', 'transpose']):
            usage_patterns['pivots'].append(text)
        
        if any(rename_word in text_lower for rename_word in ['rename', 'alias', 'as ']):
            usage_patterns['renames'].append(text)
        
        if any(output_word in text_lower for output_word in ['output', 'final', 'result', 'export']):
            usage_patterns['outputs'].append(text)
        
        if any(transform_word in text_lower for transform_word in ['transform', 'convert', 'change', 'modify']):
            usage_patterns['transformations'].append(text)
    
    return usage_patterns

def analyze_database_fields_enhanced(directory, filter_database_type, deep_analysis):
    """Enhanced analysis with comprehensive tracking and pattern recognition"""
    database_fields = defaultdict(lambda: {
        'database_type': 'Unknown',
        'server': 'Unknown',
        'database': 'Unknown',
        'schema': 'Unknown',
        'table': 'Unknown',
        'port': '',
        'used': set(),
        'unused': set(),
        'locations': set(),
        'usage_reasons': [],
        'usage_patterns': defaultdict(list),
        'transformation_count': 0,
        'resolved_tables': set(),
        'first_seen': '',
        'last_seen': '',
        'data_types': set(),
        'original_names': set(),
        'complexity_score': 0
    })
    
    database_stats = defaultdict(int)
    table_mappings = {}
    file_analysis = {}
    processed_files = 0
    total_database_refs = 0
    
    print(f"\n🚀 Starting enhanced database field analysis...")
    print(f"📁 Directory: {directory}")
    print(f"🗄️ Database filter: {filter_database_type or 'All databases'}")
    print(f"🔍 Deep analysis: {'Enabled' if deep_analysis else 'Disabled'}")
    print("=" * 100)
    
    # Walk through directory structure
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith('.zip'):
                zip_path = os.path.join(root, file)
                parent_folder = os.path.basename(os.path.dirname(zip_path))
                
                print(f"\n📦 Processing: {file}")
                file_stats = {
                    'total_fields': 0,
                    'database_fields': 0,
                    'used_fields': 0,
                    'csv_files': [],
                    'patterns_found': defaultdict(int)
                }
                
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        # Get list of all CSV files for context
                        csv_files = [f for f in zf.namelist() if f.endswith('.csv')]
                        file_stats['csv_files'] = csv_files
                        
                        # Look for relevant CSV files
                        relevant_csvs = [f for f in csv_files if any(keyword in f.lower() 
                                       for keyword in ['field', 'source', 'usage', 'input', 'transform'])]
                        
                        if relevant_csvs:
                            print(f"  📄 Found {len(relevant_csvs)} relevant CSV files")
                            
                            for csv_file in relevant_csvs:
                                print(f"    📋 Analyzing: {csv_file}")
                                
                                try:
                                    with zf.open(csv_file) as f:
                                        content = f.read().decode('utf-8')
                                        csv_reader = csv.DictReader(content.splitlines())
                                        
                                        for row in csv_reader:
                                            file_stats['total_fields'] += 1
                                            
                                            field_name = row.get('Field Name', '')
                                            data_source = row.get('Data Source', '')
                                            used = row.get('Used', '')
                                            usage_reason = row.get('Usage Reason', '')
                                            
                                            # Enhanced field information extraction
                                            data_type = row.get('Data Type', '')
                                            original_name = row.get('Original Name', '')
                                            transformation_count = row.get('Transformation Count', '0')
                                            
                                            if not field_name or not data_source:
                                                continue
                                            
                                            # Enhanced database source detection
                                            if is_database_source_enhanced(data_source):
                                                file_stats['database_fields'] += 1
                                                total_database_refs += 1
                                                
                                                db_type = get_enhanced_database_type(data_source)
                                                database_stats[db_type] += 1
                                                
                                                # Apply database type filter
                                                if filter_database_type and db_type != filter_database_type:
                                                    continue
                                                
                                                # Enhanced table resolution with context
                                                if 'Unknown' in data_source:
                                                    data_source = resolve_unknown_table_name_enhanced(
                                                        data_source, parent_folder, table_mappings, file_stats
                                                    )
                                                
                                                # Enhanced data source parsing
                                                components = parse_enhanced_data_source(data_source)
                                                
                                                # Create unique key
                                                key = (field_name, data_source)
                                                
                                                # Enhanced field information tracking
                                                field_info = database_fields[key]
                                                field_info['database_type'] = db_type
                                                field_info['server'] = components['server']
                                                field_info['database'] = components['database']
                                                field_info['schema'] = components['schema']
                                                field_info['table'] = components['table']
                                                field_info['port'] = components['port']
                                                
                                                # Track additional metadata
                                                if data_type:
                                                    field_info['data_types'].add(data_type)
                                                if original_name:
                                                    field_info['original_names'].add(original_name)
                                                
                                                # Enhanced usage tracking
                                                if used.lower() == 'yes':
                                                    field_info['used'].add(parent_folder)
                                                    file_stats['used_fields'] += 1
                                                else:
                                                    field_info['unused'].add(parent_folder)
                                                
                                                field_info['locations'].add(parent_folder)
                                                
                                                # Enhanced usage reason tracking
                                                if usage_reason:
                                                    field_info['usage_reasons'].append(f"{parent_folder}: {usage_reason}")
                                                
                                                # Deep analysis: Extract usage patterns
                                                if deep_analysis:
                                                    patterns = extract_usage_patterns_enhanced(row, deep_analysis)
                                                    for pattern_type, pattern_list in patterns.items():
                                                        field_info['usage_patterns'][pattern_type].extend(pattern_list)
                                                        file_stats['patterns_found'][pattern_type] += len(pattern_list)
                                                    
                                                    # Track transformation complexity
                                                    try:
                                                        transform_count = int(transformation_count) if transformation_count.isdigit() else 0
                                                        field_info['transformation_count'] += transform_count
                                                        field_info['complexity_score'] += transform_count * 0.5
                                                    except (ValueError, TypeError):
                                                        pass
                                                    
                                                    # Increase complexity based on usage patterns
                                                    total_patterns = sum(len(patterns[pt]) for pt in patterns)
                                                    field_info['complexity_score'] += total_patterns * 0.3
                                                
                                                # Track resolved tables
                                                if components['table'] != 'Unknown':
                                                    field_info['resolved_tables'].add(components['table'])
                                                
                                                # Track first/last seen
                                                if not field_info['first_seen']:
                                                    field_info['first_seen'] = parent_folder
                                                field_info['last_seen'] = parent_folder
                                
                                except Exception as e:
                                    print(f"      ❌ Error reading {csv_file}: {e}")
                                    continue
                        else:
                            print(f"  ⚠️ No relevant CSV files found in {file}")
                
                except Exception as e:
                    print(f"  ❌ Error processing {file}: {e}")
                    continue
                
                # Store file analysis results
                file_analysis[file] = file_stats
                processed_files += 1
                
                print(f"  📊 File summary:")
                print(f"    Total fields: {file_stats['total_fields']}")
                print(f"    Database fields: {file_stats['database_fields']}")
                print(f"    Used fields: {file_stats['used_fields']}")
                
                if deep_analysis and file_stats['patterns_found']:
                    print(f"    Pattern analysis:")
                    for pattern, count in file_stats['patterns_found'].items():
                        if count > 0:
                            print(f"      {pattern}: {count}")
    
    print(f"\n{'='*100}")
    print(f"📊 ENHANCED PROCESSING SUMMARY")
    print(f"{'='*100}")
    print(f"📦 ZIP files processed: {processed_files}")
    print(f"🗄️ Total database field references: {total_database_refs}")
    print(f"🔧 Unique field/source combinations: {len(database_fields)}")
    
    # Enhanced database statistics
    if database_stats:
        print(f"\n🗄️ Enhanced database type distribution:")
        total_refs = sum(database_stats.values())
        for db_type, count in sorted(database_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_refs * 100) if total_refs > 0 else 0
            print(f"  {db_type}: {count} references ({percentage:.1f}%)")
    
    # Table resolution statistics
    resolved_tables = sum(len(mappings) for mappings in table_mappings.values())
    if resolved_tables > 0:
        print(f"\n🔍 Enhanced table resolution statistics:")
        print(f"  Unknown tables resolved: {resolved_tables}")
        print(f"  Flows with resolved tables: {len(table_mappings)}")
        
        # Show resolution methods
        method_counts = defaultdict(int)
        for mappings in table_mappings.values():
            for mapping in mappings:
                method_counts[mapping.get('method', 'unknown')] += 1
        
        print(f"  Resolution methods used:")
        for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
            print(f"    {method}: {count}")
    
    # Deep analysis summary
    if deep_analysis:
        print(f"\n🔍 Deep analysis summary:")
        
        # Complexity analysis
        complexity_scores = [info['complexity_score'] for info in database_fields.values()]
        if complexity_scores:
            avg_complexity = sum(complexity_scores) / len(complexity_scores)
            max_complexity = max(complexity_scores)
            print(f"  Average field complexity: {avg_complexity:.2f}")
            print(f"  Maximum field complexity: {max_complexity:.2f}")
        
        # Pattern analysis
        all_patterns = defaultdict(int)
        for info in database_fields.values():
            for pattern_type, patterns in info['usage_patterns'].items():
                all_patterns[pattern_type] += len(patterns)
        
        if all_patterns:
            print(f"  Usage pattern distribution:")
            for pattern_type, count in sorted(all_patterns.items(), key=lambda x: x[1], reverse=True):
                if count > 0:
                    print(f"    {pattern_type}: {count} occurrences")
    
    return database_fields, file_analysis

def write_enhanced_results_to_csv(database_fields, output_file, filter_database_type, deep_analysis):
    """Write enhanced results with comprehensive information"""
    try:
        fieldnames = [
            'Field Name', 'Data Source', 'Database Type', 'Server', 'Database', 'Schema', 'Table', 'Port',
            'Used', 'Usage Count', 'Total Locations', 'Locations', 'Usage Reasons', 'Resolved Tables'
        ]
        
        if deep_analysis:
            fieldnames.extend([
                'Usage Patterns', 'Transformation Count', 'Complexity Score',
                'Data Types', 'Original Names', 'First Seen', 'Last Seen'
            ])
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            # Sort for consistent output
            sorted_fields = sorted(database_fields.items(), 
                                 key=lambda x: (x[1]['database_type'], x[1]['server'], 
                                              x[1]['schema'], x[1]['table'], x[0][0]))
            
            for (field_name, data_source), info in sorted_fields:
                used = "Yes" if info['used'] else "No"
                usage_count = len(info['used'])
                total_locations = len(info['locations'])
                locations = ", ".join(sorted(info['locations']))
                usage_reasons = " | ".join(info['usage_reasons']) if info['usage_reasons'] else ""
                resolved_tables = ", ".join(sorted(info['resolved_tables'])) if info['resolved_tables'] else ""
                
                row_data = {
                    'Field Name': field_name,
                    'Data Source': data_source,
                    'Database Type': info['database_type'],
                    'Server': info['server'],
                    'Database': info['database'],
                    'Schema': info['schema'],
                    'Table': info['table'],
                    'Port': info['port'],
                    'Used': used,
                    'Usage Count': usage_count,
                    'Total Locations': total_locations,
                    'Locations': locations,
                    'Usage Reasons': usage_reasons[:1000],  # Truncate very long reasons
                    'Resolved Tables': resolved_tables
                }
                
                if deep_analysis:
                    # Compile usage patterns
                    pattern_summary = []
                    for pattern_type, patterns in info['usage_patterns'].items():
                        if patterns:
                            pattern_summary.append(f"{pattern_type}: {len(patterns)}")
                    
                    row_data.update({
                        'Usage Patterns': " | ".join(pattern_summary),
                        'Transformation Count': info['transformation_count'],
                        'Complexity Score': f"{info['complexity_score']:.2f}",
                        'Data Types': ", ".join(sorted(info['data_types'])) if info['data_types'] else "",
                        'Original Names': ", ".join(sorted(info['original_names'])) if info['original_names'] else "",
                        'First Seen': info['first_seen'],
                        'Last Seen': info['last_seen']
                    })
                
                writer.writerow(row_data)
        
        print(f"\n✅ Enhanced results written to: {output_file}")
        
        # Create additional analysis files
        create_enhanced_analysis_files(database_fields, output_file, filter_database_type, deep_analysis)
        
    except Exception as e:
        print(f"❌ Error writing enhanced results: {e}")
        import traceback
        traceback.print_exc()

def create_enhanced_analysis_files(database_fields, base_output_file, filter_database_type, deep_analysis):
    """Create additional analysis files with enhanced insights"""
    base_name = base_output_file.replace('.csv', '')
    
    try:
        # 1. Table Summary Analysis
        table_summary_file = f"{base_name}_table_summary.csv"
        create_table_summary_analysis(database_fields, table_summary_file)
        
        # 2. Database Type Analysis
        db_type_summary_file = f"{base_name}_database_summary.csv"
        create_database_type_analysis(database_fields, db_type_summary_file)
        
        # 3. Usage Pattern Analysis (if deep analysis enabled)
        if deep_analysis:
            pattern_analysis_file = f"{base_name}_pattern_analysis.csv"
            create_usage_pattern_analysis(database_fields, pattern_analysis_file)
            
            # 4. Complexity Analysis
            complexity_analysis_file = f"{base_name}_complexity_analysis.csv"
            create_complexity_analysis(database_fields, complexity_analysis_file)
        
        # 5. Location Analysis
        location_analysis_file = f"{base_name}_location_analysis.csv"
        create_location_analysis(database_fields, location_analysis_file)
        
    except Exception as e:
        print(f"❌ Error creating enhanced analysis files: {e}")

def create_table_summary_analysis(database_fields, output_file):
    """Create table-level summary analysis"""
    try:
        table_summary = defaultdict(lambda: {
            'total_fields': 0,
            'used_fields': 0,
            'unique_locations': set(),
            'database_type': 'Unknown',
            'server': 'Unknown',
            'database': 'Unknown',
            'complexity_total': 0
        })
        
        for (field_name, data_source), info in database_fields.items():
            table_key = f"{info['server']}.{info['schema']}.{info['table']}"
            
            summary = table_summary[table_key]
            summary['total_fields'] += 1
            summary['database_type'] = info['database_type']
            summary['server'] = info['server']
            summary['database'] = info['database']
            summary['unique_locations'].update(info['locations'])
            summary['complexity_total'] += info.get('complexity_score', 0)
            
            if info['used']:
                summary['used_fields'] += 1
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Table', 'Database Type', 'Server', 'Database', 'Total Fields', 
                'Used Fields', 'Unused Fields', 'Usage Rate %', 'Unique Locations',
                'Location Count', 'Avg Complexity'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for table_key, summary in sorted(table_summary.items()):
                total = summary['total_fields']
                used = summary['used_fields']
                unused = total - used
                usage_rate = (used / total * 100) if total > 0 else 0
                location_count = len(summary['unique_locations'])
                avg_complexity = (summary['complexity_total'] / total) if total > 0 else 0
                
                writer.writerow({
                    'Table': table_key,
                    'Database Type': summary['database_type'],
                    'Server': summary['server'],
                    'Database': summary['database'],
                    'Total Fields': total,
                    'Used Fields': used,
                    'Unused Fields': unused,
                    'Usage Rate %': f"{usage_rate:.1f}",
                    'Unique Locations': ", ".join(sorted(summary['unique_locations'])),
                    'Location Count': location_count,
                    'Avg Complexity': f"{avg_complexity:.2f}"
                })
        
        print(f"✅ Table summary written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating table summary: {e}")

def create_database_type_analysis(database_fields, output_file):
    """Create database type analysis"""
    try:
        db_summary = defaultdict(lambda: {
            'total_fields': 0,
            'used_fields': 0,
            'unique_tables': set(),
            'unique_locations': set(),
            'servers': set()
        })
        
        for (field_name, data_source), info in database_fields.items():
            db_type = info['database_type']
            summary = db_summary[db_type]
            
            summary['total_fields'] += 1
            if info['used']:
                summary['used_fields'] += 1
            
            summary['unique_tables'].add(f"{info['server']}.{info['schema']}.{info['table']}")
            summary['unique_locations'].update(info['locations'])
            summary['servers'].add(info['server'])
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Database Type', 'Total Fields', 'Used Fields', 'Unused Fields',
                'Usage Rate %', 'Unique Tables', 'Unique Servers', 'Unique Locations'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for db_type, summary in sorted(db_summary.items(), key=lambda x: x[1]['total_fields'], reverse=True):
                total = summary['total_fields']
                used = summary['used_fields']
                unused = total - used
                usage_rate = (used / total * 100) if total > 0 else 0
                
                writer.writerow({
                    'Database Type': db_type,
                    'Total Fields': total,
                    'Used Fields': used,
                    'Unused Fields': unused,
                    'Usage Rate %': f"{usage_rate:.1f}",
                    'Unique Tables': len(summary['unique_tables']),
                    'Unique Servers': len(summary['servers']),
                    'Unique Locations': len(summary['unique_locations'])
                })
        
        print(f"✅ Database type analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating database type analysis: {e}")

def create_usage_pattern_analysis(database_fields, output_file):
    """Create usage pattern analysis for deep analysis mode"""
    try:
        pattern_summary = defaultdict(lambda: {
            'total_occurrences': 0,
            'unique_fields': set(),
            'database_types': defaultdict(int),
            'tables': set()
        })
        
        for (field_name, data_source), info in database_fields.items():
            for pattern_type, patterns in info['usage_patterns'].items():
                if patterns:
                    summary = pattern_summary[pattern_type]
                    summary['total_occurrences'] += len(patterns)
                    summary['unique_fields'].add(field_name)
                    summary['database_types'][info['database_type']] += 1
                    summary['tables'].add(f"{info['schema']}.{info['table']}")
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Pattern Type', 'Total Occurrences', 'Unique Fields', 'Unique Tables',
                'Primary Database Type', 'Database Type Distribution'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for pattern_type, summary in sorted(pattern_summary.items(), 
                                              key=lambda x: x[1]['total_occurrences'], reverse=True):
                total_occ = summary['total_occurrences']
                unique_fields = len(summary['unique_fields'])
                unique_tables = len(summary['tables'])
                
                # Find primary database type
                primary_db_type = max(summary['database_types'].items(), 
                                    key=lambda x: x[1])[0] if summary['database_types'] else 'Unknown'
                
                # Create distribution string
                db_dist = ", ".join([f"{db}: {count}" for db, count in 
                                   sorted(summary['database_types'].items(), key=lambda x: x[1], reverse=True)])
                
                writer.writerow({
                    'Pattern Type': pattern_type,
                    'Total Occurrences': total_occ,
                    'Unique Fields': unique_fields,
                    'Unique Tables': unique_tables,
                    'Primary Database Type': primary_db_type,
                    'Database Type Distribution': db_dist
                })
        
        print(f"✅ Usage pattern analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating usage pattern analysis: {e}")

def create_complexity_analysis(database_fields, output_file):
    """Create complexity analysis for deep analysis mode"""
    try:
        complexity_data = []
        
        for (field_name, data_source), info in database_fields.items():
            complexity_score = info.get('complexity_score', 0)
            transformation_count = info.get('transformation_count', 0)
            pattern_count = sum(len(patterns) for patterns in info['usage_patterns'].values())
            
            complexity_data.append({
                'Field Name': field_name,
                'Data Source': data_source,
                'Database Type': info['database_type'],
                'Table': f"{info['schema']}.{info['table']}",
                'Complexity Score': f"{complexity_score:.2f}",
                'Transformation Count': transformation_count,
                'Pattern Count': pattern_count,
                'Usage Count': len(info['used']),
                'Location Count': len(info['locations'])
            })
        
        # Sort by complexity score descending
        complexity_data.sort(key=lambda x: float(x['Complexity Score']), reverse=True)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Field Name', 'Data Source', 'Database Type', 'Table', 'Complexity Score',
                'Transformation Count', 'Pattern Count', 'Usage Count', 'Location Count'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(complexity_data)
        
        print(f"✅ Complexity analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating complexity analysis: {e}")

def create_location_analysis(database_fields, output_file):
    """Create location-based analysis"""
    try:
        location_summary = defaultdict(lambda: {
            'total_fields': 0,
            'used_fields': 0,
            'database_types': defaultdict(int),
            'unique_tables': set(),
            'unique_servers': set()
        })
        
        for (field_name, data_source), info in database_fields.items():
            for location in info['locations']:
                summary = location_summary[location]
                summary['total_fields'] += 1
                
                if info['used']:
                    summary['used_fields'] += 1
                
                summary['database_types'][info['database_type']] += 1
                summary['unique_tables'].add(f"{info['server']}.{info['schema']}.{info['table']}")
                summary['unique_servers'].add(info['server'])
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Location', 'Total Fields', 'Used Fields', 'Unused Fields', 'Usage Rate %',
                'Unique Tables', 'Unique Servers', 'Primary Database Type', 'Database Types'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for location, summary in sorted(location_summary.items()):
                total = summary['total_fields']
                used = summary['used_fields']
                unused = total - used
                usage_rate = (used / total * 100) if total > 0 else 0
                
                # Primary database type
                primary_db = max(summary['database_types'].items(), 
                               key=lambda x: x[1])[0] if summary['database_types'] else 'Unknown'
                
                db_types_str = ", ".join([f"{db}: {count}" for db, count in 
                                        sorted(summary['database_types'].items(), key=lambda x: x[1], reverse=True)])
                
                writer.writerow({
                    'Location': location,
                    'Total Fields': total,
                    'Used Fields': used,
                    'Unused Fields': unused,
                    'Usage Rate %': f"{usage_rate:.1f}",
                    'Unique Tables': len(summary['unique_tables']),
                    'Unique Servers': len(summary['unique_servers']),
                    'Primary Database Type': primary_db,
                    'Database Types': db_types_str
                })
        
        print(f"✅ Location analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating location analysis: {e}")

def main():
    """Main function with comprehensive enhanced interactive interface"""
    try:
        directory, output_file, filter_database_type, deep_analysis = get_user_inputs()
        
        print("🚀 Starting comprehensive enhanced database field analysis...")
        database_fields, file_analysis = analyze_database_fields_enhanced(directory, filter_database_type, deep_analysis)
        
        if not database_fields:
            print("\n❌ No database fields found to analyze")
            print("   This could mean:")
            print("   • No ZIP files with CSV analysis results in the directory")
            print("   • No database sources found (only file sources)")
            print("   • Database filter excluded all found sources")
            return
        
        write_enhanced_results_to_csv(database_fields, output_file, filter_database_type, deep_analysis)
        
        print(f"\n{'='*100}")
        print(f"📊 ENHANCED ANALYSIS COMPLETE")
        print(f"{'='*100}")
        print(f"🔧 Unique field/source combinations: {len(database_fields)}")
        
        # Enhanced usage statistics
        total_used = sum(1 for info in database_fields.values() if info['used'])
        total_unused = len(database_fields) - total_used
        usage_rate = (total_used / len(database_fields) * 100) if database_fields else 0
        
        print(f"✅ Used fields: {total_used}")
        print(f"❌ Unused fields: {total_unused}")
        print(f"📈 Overall usage rate: {usage_rate:.1f}%")
        
        # Enhanced database type breakdown
        db_breakdown = defaultdict(lambda: {'total': 0, 'used': 0, 'complexity': 0})
        for info in database_fields.values():
            db_type = info['database_type']
            db_breakdown[db_type]['total'] += 1
            if info['used']:
                db_breakdown[db_type]['used'] += 1
            db_breakdown[db_type]['complexity'] += info.get('complexity_score', 0)
        
        print(f"\n🗄️ Enhanced breakdown by database type:")
        for db_type, stats in sorted(db_breakdown.items(), key=lambda x: x[1]['total'], reverse=True):
            total = stats['total']
            used = stats['used']
            unused = total - used
            db_usage_rate = (used / total * 100) if total > 0 else 0
            avg_complexity = (stats['complexity'] / total) if total > 0 else 0
            
            print(f"  {db_type}:")
            print(f"    Total: {total} fields")
            print(f"    Used: {used} fields ({db_usage_rate:.1f}%)")
            print(f"    Unused: {unused} fields")
            if deep_analysis:
                print(f"    Avg Complexity: {avg_complexity:.2f}")
        
        # Enhanced table statistics
        unique_tables = set()
        unique_servers = set()
        for info in database_fields.values():
            if info['table'] != 'Unknown':
                table_key = f"{info['database_type']}.{info['server']}.{info['schema']}.{info['table']}"
                unique_tables.add(table_key)
                unique_servers.add(info['server'])
        
        print(f"\n📋 Enhanced table statistics:")
        print(f"  Unique tables referenced: {len(unique_tables)}")
        print(f"  Unique servers referenced: {len(unique_servers)}")
        
        # Enhanced location statistics
        all_locations = set()
        location_usage = defaultdict(lambda: {'total': 0, 'used': 0})
        
        for info in database_fields.values():
            all_locations.update(info['locations'])
            for location in info['locations']:
                location_usage[location]['total'] += 1
                if info['used']:
                    location_usage[location]['used'] += 1
        
        print(f"  Unique flow locations: {len(all_locations)}")
        
        # Show top locations by field count
        top_locations = sorted(location_usage.items(), key=lambda x: x[1]['total'], reverse=True)[:5]
        if top_locations:
            print(f"  Top locations by field count:")
            for location, stats in top_locations:
                usage_pct = (stats['used'] / stats['total'] * 100) if stats['total'] > 0 else 0
                print(f"    {location}: {stats['total']} fields ({usage_pct:.1f}% used)")
        
        # File processing summary
        successful_files = sum(1 for stats in file_analysis.values() if stats['database_fields'] > 0)
        total_files = len(file_analysis)
        
        print(f"\n📁 File processing summary:")
        print(f"  Total files processed: {total_files}")
        print(f"  Files with database fields: {successful_files}")
        print(f"  Success rate: {(successful_files/total_files*100):.1f}%" if total_files > 0 else "Success rate: 0%")
        
        # Deep analysis summary
        if deep_analysis:
            print(f"\n🔍 Deep analysis insights:")
            
            # Complexity analysis
            complexity_scores = [info['complexity_score'] for info in database_fields.values()]
            if complexity_scores:
                avg_complexity = sum(complexity_scores) / len(complexity_scores)
                max_complexity = max(complexity_scores)
                print(f"  Average field complexity: {avg_complexity:.2f}")
                print(f"  Maximum field complexity: {max_complexity:.2f}")
                
                # Find most complex fields
                complex_fields = sorted(
                    [(key, info['complexity_score']) for key, info in database_fields.items()],
                    key=lambda x: x[1], reverse=True
                )[:3]
                
                print(f"  Most complex fields:")
                for (field_name, data_source), score in complex_fields:
                    print(f"    {field_name} ({score:.2f}): {data_source[:50]}...")
            
            # Pattern analysis summary
            all_patterns = defaultdict(int)
            for info in database_fields.values():
                for pattern_type, patterns in info['usage_patterns'].items():
                    all_patterns[pattern_type] += len(patterns)
            
            if all_patterns:
                print(f"  Usage pattern distribution:")
                for pattern_type, count in sorted(all_patterns.items(), key=lambda x: x[1], reverse=True)[:5]:
                    if count > 0:
                        print(f"    {pattern_type}: {count} occurrences")
            
            # Transformation analysis
            total_transformations = sum(info['transformation_count'] for info in database_fields.values())
            avg_transformations = total_transformations / len(database_fields) if database_fields else 0
            print(f"  Total transformations tracked: {total_transformations}")
            print(f"  Average transformations per field: {avg_transformations:.1f}")
        
        if filter_database_type:
            print(f"\n🔍 Filter applied: {filter_database_type} only")
        
        # Output file summary
        print(f"\n📁 Results saved to:")
        print(f"  Main results: {output_file}")
        
        base_name = output_file.replace('.csv', '')
        additional_files = [
            f"{base_name}_table_summary.csv",
            f"{base_name}_database_summary.csv",
            f"{base_name}_location_analysis.csv"
        ]
        
        if deep_analysis:
            additional_files.extend([
                f"{base_name}_pattern_analysis.csv",
                f"{base_name}_complexity_analysis.csv"
            ])
        
        for additional_file in additional_files:
            if os.path.exists(additional_file):
                print(f"  {os.path.basename(additional_file)}")
        
        total_output_files = 1 + len([f for f in additional_files if os.path.exists(f)])
        print(f"\n📊 Generated {total_output_files} analysis files")
        
        if deep_analysis:
            print(f"🔍 Deep analysis provided enhanced insights into:")
            print(f"  • Field complexity scoring")
            print(f"  • Usage pattern categorization")
            print(f"  • Transformation tracking")
            print(f"  • Advanced table resolution")
        
        print(f"\n🎉 Enhanced analysis complete!")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Critical error during enhanced analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()