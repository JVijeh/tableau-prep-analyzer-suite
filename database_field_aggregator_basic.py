import os
import csv
import zipfile
from pathlib import Path
from collections import defaultdict
import re
from datetime import datetime

def get_user_inputs():
    """Interactive prompts for user inputs"""
    print("=== Database Field Aggregator - Basic Version ===")
    print("Aggregate field usage across multiple Tableau Prep flow analyses")
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
    
    return directory, output_file, filter_database_type

def is_database_source(data_source):
    """Enhanced check if a data source is a database connection"""
    if not data_source or data_source == 'Unknown':
        return False
    
    # Check for database patterns - exclude file sources
    file_indicators = ['File:', 'CSV/Text File:', 'Excel File:', 'JSON File:']
    if any(indicator in data_source for indicator in file_indicators):
        return False
    
    # Check for database indicators
    database_indicators = [
        'Oracle:', 'SQL Server:', 'PostgreSQL:', 'MySQL:', 'Database:',
        'Teradata:', 'Snowflake:', 'Redshift:', 'BigQuery:', 'Databricks:'
    ]
    
    if any(indicator in data_source for indicator in database_indicators):
        return True
    
    # Check for server.schema.table pattern (likely database)
    if re.match(r'^[^:]+\.[^:]+\.[^:]+$', data_source.strip()):
        return True
    
    # Check for Tableau Server published data sources (these could be database-backed)
    if 'Tableau Server:' in data_source:
        return True  # Include these as they often represent database sources
    
    return False

def get_database_type_from_source(data_source):
    """Enhanced database type detection with comprehensive patterns"""
    if not data_source:
        return 'Unknown'
    
    data_source_lower = data_source.lower()
    
    # Direct database type indicators
    if data_source.startswith('Oracle:'):
        return 'Oracle'
    elif data_source.startswith('SQL Server:'):
        return 'SQL Server'
    elif data_source.startswith('PostgreSQL:'):
        return 'PostgreSQL'
    elif data_source.startswith('MySQL:'):
        return 'MySQL'
    elif data_source.startswith('Teradata:'):
        return 'Teradata'
    elif data_source.startswith('Snowflake:'):
        return 'Snowflake'
    elif data_source.startswith('Redshift:'):
        return 'Redshift'
    elif data_source.startswith('BigQuery:'):
        return 'BigQuery'
    elif data_source.startswith('Databricks:'):
        return 'Databricks'
    elif data_source.startswith('Database:'):
        return 'Database'
    elif data_source.startswith('Tableau Server:'):
        return 'Tableau Server'
    
    # Pattern-based detection for cases without explicit prefixes
    db_patterns = {
        'Oracle': ['oracle', 'ora_', 'orcl', 'xe', 'sid='],
        'SQL Server': ['sqlserver', 'mssql', 'microsoft', 'tsql', '.dbo.'],
        'PostgreSQL': ['postgres', 'postgresql', 'psql', 'pg_'],
        'MySQL': ['mysql', 'mariadb', 'my_'],
        'Teradata': ['teradata', 'td_'],
        'Snowflake': ['snowflake', 'snow_'],
        'Redshift': ['redshift', 'rs_'],
        'BigQuery': ['bigquery', 'bq_'],
        'Databricks': ['databricks', 'spark']
    }
    
    for db_type, patterns in db_patterns.items():
        if any(pattern in data_source_lower for pattern in patterns):
            return db_type
    
    return 'Other'

def parse_data_source_components(data_source):
    """Parse data source into server, schema, table components"""
    components = {
        'server': 'Unknown',
        'schema': 'Unknown', 
        'table': 'Unknown',
        'full_name': data_source
    }
    
    # Handle prefixed data sources (e.g., "Oracle: server.schema.table")
    if ':' in data_source:
        prefix, connection_string = data_source.split(':', 1)
        connection_string = connection_string.strip()
    else:
        connection_string = data_source
    
    # Parse server.schema.table pattern
    parts = connection_string.split('.')
    if len(parts) >= 3:
        components['server'] = parts[0].strip()
        components['schema'] = parts[1].strip()
        components['table'] = parts[2].strip('[]"`')
    elif len(parts) == 2:
        components['schema'] = parts[0].strip()
        components['table'] = parts[1].strip('[]"`')
    elif len(parts) == 1:
        components['table'] = parts[0].strip('[]"`')
    
    return components

def resolve_table_name(data_source, parent_folder, table_mappings):
    """Enhanced table name resolution with multiple strategies"""
    if 'Unknown' not in data_source:
        return data_source
    
    print(f"    🔍 Resolving 'Unknown' table in: {data_source}")
    
    # Strategy 1: Check existing mappings
    if parent_folder in table_mappings:
        for mapping in table_mappings[parent_folder]:
            if 'Unknown' in mapping['original']:
                resolved = data_source.replace('Unknown', mapping['resolved'])
                print(f"    ✅ Resolved using mapping: {resolved}")
                return resolved
    
    # Strategy 2: Pattern matching in folder names
    folder_lower = parent_folder.lower()
    
    table_patterns = [
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
        r'(\w+_summary)'
    ]
    
    for pattern in table_patterns:
        match = re.search(pattern, folder_lower)
        if match:
            potential_table = match.group(1)
            resolved_source = data_source.replace('Unknown', potential_table)
            
            # Store this resolution
            if parent_folder not in table_mappings:
                table_mappings[parent_folder] = []
            table_mappings[parent_folder].append({
                'original': data_source,
                'resolved': potential_table
            })
            
            print(f"    ✅ Resolved using pattern: {resolved_source}")
            return resolved_source
    
    # Strategy 3: Use cleaned folder name
    clean_folder = re.sub(r'[^a-zA-Z0-9_]', '_', parent_folder)
    clean_folder = re.sub(r'_+', '_', clean_folder).strip('_')
    
    if clean_folder:
        resolved_source = data_source.replace('Unknown', clean_folder)
        
        # Store this resolution
        if parent_folder not in table_mappings:
            table_mappings[parent_folder] = []
        table_mappings[parent_folder].append({
            'original': data_source,
            'resolved': clean_folder
        })
        
        print(f"    ✅ Resolved using folder name: {resolved_source}")
        return resolved_source
    
    print(f"    ❌ Could not resolve: {data_source}")
    return data_source

def analyze_database_fields(directory, filter_database_type):
    """Comprehensive analysis of database fields from CSV files"""
    database_fields = defaultdict(lambda: {
        'database_type': 'Unknown',
        'server': 'Unknown',
        'schema': 'Unknown',
        'table': 'Unknown',
        'used': set(),
        'unused': set(),
        'locations': set(),
        'usage_reasons': [],
        'first_seen': '',
        'last_seen': ''
    })
    
    database_stats = defaultdict(int)
    table_mappings = {}
    file_stats = {
        'total_files': 0,
        'processed_files': 0,
        'csv_files_found': 0,
        'database_fields_found': 0
    }
    
    print(f"\n🔍 Starting comprehensive database field analysis...")
    print(f"📁 Directory: {directory}")
    print(f"🗄️ Database filter: {filter_database_type or 'All databases'}")
    print("=" * 80)
    
    # Walk through directory structure
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_stats['total_files'] += 1
            
            if file.endswith('.zip'):
                zip_path = os.path.join(root, file)
                parent_folder = os.path.basename(os.path.dirname(zip_path))
                
                print(f"\n📦 Processing: {file}")
                file_processed = False
                
                try:
                    with zipfile.ZipFile(zip_path, 'r') as zf:
                        # Look for field usage CSV files
                        csv_files = [f for f in zf.namelist() if f.endswith('.csv')]
                        relevant_csvs = [f for f in csv_files if any(keyword in f.lower() for keyword in ['field', 'source', 'usage', 'input'])]
                        
                        if relevant_csvs:
                            file_stats['csv_files_found'] += len(relevant_csvs)
                            
                            for csv_file in relevant_csvs:
                                print(f"  📄 Reading: {csv_file}")
                                
                                try:
                                    with zf.open(csv_file) as f:
                                        content = f.read().decode('utf-8')
                                        csv_reader = csv.DictReader(content.splitlines())
                                        
                                        for row in csv_reader:
                                            field_name = row.get('Field Name', '')
                                            data_source = row.get('Data Source', '')
                                            used = row.get('Used', '')
                                            usage_reason = row.get('Usage Reason', '')
                                            
                                            if not field_name or not data_source:
                                                continue
                                            
                                            # Check if this is a database source
                                            if is_database_source(data_source):
                                                file_stats['database_fields_found'] += 1
                                                db_type = get_database_type_from_source(data_source)
                                                database_stats[db_type] += 1
                                                
                                                # Apply database type filter
                                                if filter_database_type and db_type != filter_database_type:
                                                    continue
                                                
                                                # Resolve unknown table names
                                                if 'Unknown' in data_source:
                                                    data_source = resolve_table_name(data_source, parent_folder, table_mappings)
                                                
                                                # Parse data source components
                                                components = parse_data_source_components(data_source)
                                                
                                                # Create unique key for this field/source combination
                                                key = (field_name, data_source)
                                                
                                                # Update field information
                                                field_info = database_fields[key]
                                                field_info['database_type'] = db_type
                                                field_info['server'] = components['server']
                                                field_info['schema'] = components['schema']
                                                field_info['table'] = components['table']
                                                
                                                # Track usage
                                                if used.lower() == 'yes':
                                                    field_info['used'].add(parent_folder)
                                                else:
                                                    field_info['unused'].add(parent_folder)
                                                
                                                field_info['locations'].add(parent_folder)
                                                
                                                # Track usage reasons
                                                if usage_reason:
                                                    field_info['usage_reasons'].append(f"{parent_folder}: {usage_reason}")
                                                
                                                # Track first/last seen
                                                if not field_info['first_seen']:
                                                    field_info['first_seen'] = parent_folder
                                                field_info['last_seen'] = parent_folder
                                                
                                                file_processed = True
                                
                                except Exception as e:
                                    print(f"    ❌ Error reading {csv_file}: {e}")
                                    continue
                        else:
                            print(f"  ⚠️ No relevant CSV files found in {file}")
                
                except Exception as e:
                    print(f"  ❌ Error processing {file}: {e}")
                    continue
                
                if file_processed:
                    file_stats['processed_files'] += 1
                    print(f"  ✅ Successfully processed: {file}")
                else:
                    print(f"  ⚠️ No database fields found in: {file}")
    
    print(f"\n{'='*80}")
    print(f"📊 PROCESSING STATISTICS")
    print(f"{'='*80}")
    print(f"📁 Total files scanned: {file_stats['total_files']}")
    print(f"📦 ZIP files processed: {file_stats['processed_files']}")
    print(f"📄 CSV files analyzed: {file_stats['csv_files_found']}")
    print(f"🗄️ Database field references found: {file_stats['database_fields_found']}")
    print(f"🔧 Unique field/source combinations: {len(database_fields)}")
    
    # Database type statistics
    if database_stats:
        print(f"\n🗄️ Database type distribution:")
        total_refs = sum(database_stats.values())
        for db_type, count in sorted(database_stats.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total_refs * 100) if total_refs > 0 else 0
            print(f"  {db_type}: {count} references ({percentage:.1f}%)")
    
    # Table resolution statistics
    resolved_tables = sum(len(mappings) for mappings in table_mappings.values())
    if resolved_tables > 0:
        print(f"\n🔍 Table resolution statistics:")
        print(f"  Unknown tables resolved: {resolved_tables}")
        print(f"  Flows with resolved tables: {len(table_mappings)}")
    
    return database_fields

def write_results_to_csv(database_fields, output_file, filter_database_type):
    """Write comprehensive results to CSV file"""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Field Name', 'Data Source', 'Database Type', 'Server', 'Schema', 'Table',
                'Used', 'Usage Count', 'Total Locations', 'Locations', 'Usage Reasons'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            # Sort results for consistent output
            sorted_fields = sorted(database_fields.items(), 
                                 key=lambda x: (x[1]['database_type'], x[1]['server'], x[1]['schema'], x[1]['table'], x[0][0]))
            
            for (field_name, data_source), info in sorted_fields:
                # Determine overall usage
                used = "Yes" if info['used'] else "No"
                usage_count = len(info['used'])
                total_locations = len(info['locations'])
                
                # Create locations list
                locations = ", ".join(sorted(info['locations']))
                
                # Compile usage reasons
                usage_reasons = " | ".join(info['usage_reasons']) if info['usage_reasons'] else ""
                
                writer.writerow({
                    'Field Name': field_name,
                    'Data Source': data_source,
                    'Database Type': info['database_type'],
                    'Server': info['server'],
                    'Schema': info['schema'],
                    'Table': info['table'],
                    'Used': used,
                    'Usage Count': usage_count,
                    'Total Locations': total_locations,
                    'Locations': locations,
                    'Usage Reasons': usage_reasons[:500]  # Truncate very long reasons
                })
        
        print(f"\n✅ Results written to: {output_file}")
        
        # Create summary file
        summary_file = output_file.replace('.csv', '_summary.csv')
        write_summary_file(database_fields, summary_file, filter_database_type)
        
    except Exception as e:
        print(f"❌ Error writing results: {e}")

def write_summary_file(database_fields, summary_file, filter_database_type):
    """Write detailed summary analysis"""
    try:
        with open(summary_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Database Type', 'Server', 'Schema', 'Table', 
                'Total Fields', 'Used Fields', 'Unused Fields', 
                'Usage Rate %', 'Unique Locations'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            # Aggregate by table
            table_summary = defaultdict(lambda: {
                'total_fields': 0,
                'used_fields': 0,
                'locations': set()
            })
            
            for (field_name, data_source), info in database_fields.items():
                table_key = (info['database_type'], info['server'], info['schema'], info['table'])
                
                table_summary[table_key]['total_fields'] += 1
                if info['used']:
                    table_summary[table_key]['used_fields'] += 1
                table_summary[table_key]['locations'].update(info['locations'])
            
            # Sort by database type, then server, schema, table
            sorted_tables = sorted(table_summary.items(), key=lambda x: x[0])
            
            for (db_type, server, schema, table), stats in sorted_tables:
                total_fields = stats['total_fields']
                used_fields = stats['used_fields']
                unused_fields = total_fields - used_fields
                usage_rate = (used_fields / total_fields * 100) if total_fields > 0 else 0
                unique_locations = len(stats['locations'])
                
                writer.writerow({
                    'Database Type': db_type,
                    'Server': server,
                    'Schema': schema,
                    'Table': table,
                    'Total Fields': total_fields,
                    'Used Fields': used_fields,
                    'Unused Fields': unused_fields,
                    'Usage Rate %': f"{usage_rate:.1f}",
                    'Unique Locations': unique_locations
                })
        
        print(f"✅ Summary written to: {summary_file}")
        
    except Exception as e:
        print(f"❌ Error writing summary: {e}")

def main():
    """Main function with comprehensive interactive interface"""
    try:
        directory, output_file, filter_database_type = get_user_inputs()
        
        print("🚀 Starting comprehensive database field analysis with table name resolution...")
        database_fields = analyze_database_fields(directory, filter_database_type)
        
        if not database_fields:
            print("\n❌ No database fields found to analyze")
            print("   This could mean:")
            print("   • No ZIP files with CSV analysis results in the directory")
            print("   • No database sources found (only file sources)")
            print("   • Database filter excluded all found sources")
            return
        
        write_results_to_csv(database_fields, output_file, filter_database_type)
        
        print(f"\n{'='*80}")
        print(f"📊 ANALYSIS COMPLETE")
        print(f"{'='*80}")
        print(f"🔧 Unique field/source combinations: {len(database_fields)}")
        
        # Usage statistics
        total_used = sum(1 for info in database_fields.values() if info['used'])
        total_unused = len(database_fields) - total_used
        usage_rate = (total_used / len(database_fields) * 100) if database_fields else 0
        
        print(f"✅ Used fields: {total_used}")
        print(f"❌ Unused fields: {total_unused}")
        print(f"📈 Overall usage rate: {usage_rate:.1f}%")
        
        # Database type breakdown
        db_breakdown = defaultdict(lambda: {'total': 0, 'used': 0})
        for info in database_fields.values():
            db_type = info['database_type']
            db_breakdown[db_type]['total'] += 1
            if info['used']:
                db_breakdown[db_type]['used'] += 1
        
        print(f"\n🗄️ Breakdown by database type:")
        for db_type, stats in sorted(db_breakdown.items()):
            total = stats['total']
            used = stats['used']
            unused = total - used
            db_usage_rate = (used / total * 100) if total > 0 else 0
            print(f"  {db_type}:")
            print(f"    Total: {total} fields")
            print(f"    Used: {used} fields ({db_usage_rate:.1f}%)")
            print(f"    Unused: {unused} fields")
        
        # Table statistics
        unique_tables = set()
        for info in database_fields.values():
            if info['table'] != 'Unknown':
                table_key = f"{info['database_type']}.{info['server']}.{info['schema']}.{info['table']}"
                unique_tables.add(table_key)
        
        print(f"\n📋 Table statistics:")
        print(f"  Unique tables referenced: {len(unique_tables)}")
        
        # Location statistics
        all_locations = set()
        for info in database_fields.values():
            all_locations.update(info['locations'])
        
        print(f"  Unique flow locations: {len(all_locations)}")
        
        if filter_database_type:
            print(f"\n🔍 Filter applied: {filter_database_type} only")
        
        print(f"\n📁 Results saved to:")
        print(f"  Main results: {output_file}")
        print(f"  Summary: {output_file.replace('.csv', '_summary.csv')}")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Critical error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()