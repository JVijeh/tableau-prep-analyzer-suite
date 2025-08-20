import os
import csv
import zipfile
import json
import xml.etree.ElementTree as ET
from io import TextIOWrapper
from collections import defaultdict
import re
import tempfile
import shutil

def get_user_inputs():
    """Interactive prompts for user inputs"""
    print("=== Table Mapping Extraction - Basic Version ===")
    print("Extract table names and relationships from Tableau Prep flow files")
    print()
    
    # Get input file
    while True:
        file_path = input("Enter the path to the .tfl or .tflx file: ").strip()
        if os.path.exists(file_path):
            break
        print(f"Error: File '{file_path}' does not exist. Please try again.")
    
    # Get output option
    output_csv = input("Enter output CSV file name (press Enter to skip CSV export): ").strip()
    if output_csv and not output_csv.endswith('.csv'):
        output_csv += '.csv'
    
    return file_path, output_csv

def extract_table_mappings(file_path):
    """Extract comprehensive table mappings from flow file with multiple extraction methods"""
    table_mappings = {}
    extraction_stats = {
        'json_extractions': 0,
        'xml_extractions': 0,
        'pattern_extractions': 0,
        'connection_extractions': 0
    }
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        print(f"\n🔍 Extracting table mappings from: {file_path}")
        
        if file_path.endswith('.tfl'):
            # Direct JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                extracted = extract_tables_from_json_content(content)
                table_mappings.update(extracted)
                extraction_stats['json_extractions'] += len(extracted)
                
        elif file_path.endswith('.tflx'):
            # ZIP archive - comprehensive extraction
            with zipfile.ZipFile(file_path, 'r') as zf:
                zf.extractall(temp_dir)
                
                print("  📁 Analyzing archive contents...")
                
                # Process all files in the archive
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path_full = os.path.join(root, file)
                        
                        try:
                            if file.lower() in ['flow', 'flow.json'] or file.endswith('.json'):
                                print(f"    📄 Processing JSON file: {file}")
                                with open(file_path_full, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    extracted = extract_tables_from_json_content(content)
                                    table_mappings.update(extracted)
                                    extraction_stats['json_extractions'] += len(extracted)
                            
                            elif file.endswith(('.xml', '.twb', '.tds')):
                                print(f"    📄 Processing XML file: {file}")
                                with open(file_path_full, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    extracted = extract_tables_from_xml_content(content)
                                    table_mappings.update(extracted)
                                    extraction_stats['xml_extractions'] += len(extracted)
                            
                            elif any(keyword in file.lower() for keyword in ['connection', 'datasource']):
                                print(f"    📄 Processing connection file: {file}")
                                with open(file_path_full, 'r', encoding='utf-8') as f:
                                    content = f.read()
                                    extracted = extract_tables_from_connection_content(content)
                                    table_mappings.update(extracted)
                                    extraction_stats['connection_extractions'] += len(extracted)
                        
                        except Exception as e:
                            print(f"      ⚠️ Could not process {file}: {e}")
                            continue
        else:
            print(f"❌ Unsupported file type: {file_path}")
            return table_mappings, extraction_stats
        
        print(f"\n📊 Extraction summary:")
        print(f"  JSON extractions: {extraction_stats['json_extractions']}")
        print(f"  XML extractions: {extraction_stats['xml_extractions']}")
        print(f"  Connection extractions: {extraction_stats['connection_extractions']}")
        print(f"  Total tables found: {len(table_mappings)}")
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")
    
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    return table_mappings, extraction_stats

def extract_tables_from_json_content(content):
    """Comprehensive table extraction from JSON content with multiple strategies"""
    table_mappings = {}
    
    try:
        data = json.loads(content)
        
        # Strategy 1: Process nodes structure
        if 'nodes' in data and isinstance(data['nodes'], dict):
            for node_id, node in data['nodes'].items():
                extracted_tables = extract_tables_from_node(node, node_id)
                table_mappings.update(extracted_tables)
        
        # Strategy 2: Process connections structure
        if 'connections' in data and isinstance(data['connections'], dict):
            for conn_id, conn_info in data['connections'].items():
                extracted_tables = extract_tables_from_connection(conn_info, conn_id)
                table_mappings.update(extracted_tables)
        
        # Strategy 3: Recursive search for any table references
        recursive_tables = extract_tables_from_json_recursive(data)
        table_mappings.update(recursive_tables)
        
    except json.JSONDecodeError:
        # Strategy 4: Pattern-based extraction for malformed JSON
        pattern_tables = extract_tables_from_text_patterns(content)
        table_mappings.update(pattern_tables)
    
    return table_mappings

def extract_tables_from_node(node, node_id):
    """Extract table information from a flow node"""
    tables = {}
    
    if not isinstance(node, dict):
        return tables
    
    node_name = node.get('name', f'Node_{node_id}')
    node_type = node.get('nodeType', 'unknown')
    
    # Method 1: Check relation structure
    if 'relation' in node:
        relation = node['relation']
        if isinstance(relation, dict):
            table_info = extract_table_from_relation(relation, node_name, node_id)
            if table_info:
                tables[table_info['table']] = table_info
    
    # Method 2: Check connectionAttributes
    if 'connectionAttributes' in node:
        conn_attrs = node['connectionAttributes']
        if isinstance(conn_attrs, dict):
            table_info = extract_table_from_connection_attributes(conn_attrs, node_name, node_id)
            if table_info:
                tables[table_info['table']] = table_info
    
    # Method 3: Check nested containers
    if 'loomContainer' in node:
        loom_container = node['loomContainer']
        if isinstance(loom_container, dict) and 'nodes' in loom_container:
            for sub_node_id, sub_node in loom_container['nodes'].items():
                sub_tables = extract_tables_from_node(sub_node, sub_node_id)
                tables.update(sub_tables)
    
    return tables

def extract_table_from_relation(relation, node_name, node_id):
    """Extract table information from relation object"""
    table = relation.get('table', '').strip()
    
    if not table or table == 'Unknown':
        return None
    
    # Clean table name
    table = table.strip('[]"`\'')
    
    schema = relation.get('schema', '').strip()
    database = relation.get('database', '').strip()
    
    # Build full name
    name_parts = [part for part in [database, schema, table] if part]
    full_name = '.'.join(name_parts)
    
    return {
        'table': table,
        'schema': schema,
        'database': database,
        'full_name': full_name,
        'node_name': node_name,
        'node_id': node_id,
        'extraction_method': 'relation_structure'
    }

def extract_table_from_connection_attributes(conn_attrs, node_name, node_id):
    """Extract table information from connection attributes"""
    # Multiple ways to specify table
    table = (
        conn_attrs.get('table') or 
        conn_attrs.get('relation') or 
        conn_attrs.get('tableName') or 
        ''
    ).strip()
    
    if not table or table == 'Unknown':
        return None
    
    # Clean table name
    table = table.strip('[]"`\'')
    
    schema = (
        conn_attrs.get('schema') or 
        conn_attrs.get('owner') or 
        ''
    ).strip()
    
    database = (
        conn_attrs.get('database') or 
        conn_attrs.get('dbname') or 
        conn_attrs.get('catalog') or 
        ''
    ).strip()
    
    server = (
        conn_attrs.get('server') or 
        conn_attrs.get('hostname') or 
        conn_attrs.get('host') or 
        ''
    ).strip()
    
    # Determine database type from connection class
    db_class = conn_attrs.get('class', '').lower()
    db_type = determine_database_type_from_class(db_class)
    
    # Build full name
    name_parts = [part for part in [server, database, schema, table] if part]
    full_name = '.'.join(name_parts)
    
    return {
        'table': table,
        'schema': schema,
        'database': database,
        'server': server,
        'full_name': full_name,
        'database_type': db_type,
        'connection_class': db_class,
        'node_name': node_name,
        'node_id': node_id,
        'extraction_method': 'connection_attributes'
    }

def extract_tables_from_connection(conn_info, conn_id):
    """Extract table information from connection definition"""
    tables = {}
    
    if not isinstance(conn_info, dict):
        return tables
    
    # Look for table references in connection info
    table_fields = ['table', 'relation', 'tableName', 'defaultTable']
    
    for field in table_fields:
        if field in conn_info:
            table = conn_info[field].strip() if conn_info[field] else ''
            if table and table != 'Unknown':
                table = table.strip('[]"`\'')
                
                schema = conn_info.get('schema', '').strip()
                database = conn_info.get('database', '').strip()
                server = conn_info.get('server', '').strip()
                
                db_class = conn_info.get('class', '').lower()
                db_type = determine_database_type_from_class(db_class)
                
                name_parts = [part for part in [server, database, schema, table] if part]
                full_name = '.'.join(name_parts)
                
                tables[table] = {
                    'table': table,
                    'schema': schema,
                    'database': database,
                    'server': server,
                    'full_name': full_name,
                    'database_type': db_type,
                    'connection_class': db_class,
                    'connection_id': conn_id,
                    'extraction_method': 'connection_definition'
                }
    
    return tables

def extract_tables_from_json_recursive(data, path=""):
    """Recursively search for table references in JSON structure"""
    tables = {}
    
    if isinstance(data, dict):
        # Look for table-related keys
        table_keys = ['table', 'tableName', 'relation', 'relationName', 'dataSource']
        
        for key, value in data.items():
            if key in table_keys and isinstance(value, str) and value.strip() and value != 'Unknown':
                table = value.strip('[]"`\'')
                
                # Try to find associated schema/database in same dict
                schema = data.get('schema', data.get('owner', '')).strip()
                database = data.get('database', data.get('dbname', '')).strip()
                
                name_parts = [part for part in [database, schema, table] if part]
                full_name = '.'.join(name_parts)
                
                tables[table] = {
                    'table': table,
                    'schema': schema,
                    'database': database,
                    'full_name': full_name,
                    'json_path': path,
                    'extraction_method': 'recursive_search'
                }
            
            # Recurse into nested structures
            elif isinstance(value, (dict, list)):
                nested_tables = extract_tables_from_json_recursive(value, f"{path}.{key}" if path else key)
                tables.update(nested_tables)
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                nested_tables = extract_tables_from_json_recursive(item, f"{path}[{i}]")
                tables.update(nested_tables)
    
    return tables

def extract_tables_from_text_patterns(content):
    """Extract table names using regex patterns for malformed JSON"""
    tables = {}
    
    # Enhanced regex patterns for table extraction
    table_patterns = [
        r'"table"\s*:\s*"([^"]+)"',
        r'"tableName"\s*:\s*"([^"]+)"',
        r'"relation"\s*:\s*"([^"]+)"',
        r'"relationName"\s*:\s*"([^"]+)"',
        r'"dataSource"\s*:\s*"([^"]+)"',
        r'"name"\s*:\s*"([^"\.]+\.[^"\.]+\.[^"]+)"',  # Full database.schema.table
        r'FROM\s+([^\s;]+)',  # SQL FROM clauses
        r'INSERT\s+INTO\s+([^\s(]+)',  # SQL INSERT statements
        r'UPDATE\s+([^\s]+)',  # SQL UPDATE statements
    ]
    
    for i, pattern in enumerate(table_patterns):
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if match and match != 'Unknown':
                # Clean the match
                table = match.strip('[]"`\'')
                
                # Handle full qualified names
                if '.' in table and len(table.split('.')) >= 2:
                    parts = table.split('.')
                    if len(parts) == 3:
                        database, schema, table_name = parts
                    elif len(parts) == 2:
                        schema, table_name = parts
                        database = ''
                    else:
                        table_name = table
                        schema = database = ''
                    
                    full_name = '.'.join(part for part in [database, schema, table_name] if part)
                    
                    tables[table_name] = {
                        'table': table_name,
                        'schema': schema,
                        'database': database,
                        'full_name': full_name,
                        'pattern_match': pattern,
                        'extraction_method': f'pattern_{i+1}'
                    }
                else:
                    tables[table] = {
                        'table': table,
                        'schema': '',
                        'database': '',
                        'full_name': table,
                        'pattern_match': pattern,
                        'extraction_method': f'pattern_{i+1}'
                    }
    
    return tables

def extract_tables_from_xml_content(content):
    """Extract table names from XML content with comprehensive parsing"""
    tables = {}
    
    try:
        # Try to parse as proper XML
        root = ET.fromstring(content)
        
        # Look for table-related elements and attributes
        for elem in root.iter():
            # Check element attributes
            for attr_name, attr_value in elem.attrib.items():
                if (any(keyword in attr_name.lower() for keyword in ['table', 'relation']) and 
                    attr_value and attr_value != 'Unknown'):
                    
                    table = attr_value.strip('[]"`\'')
                    tables[table] = {
                        'table': table,
                        'schema': '',
                        'database': '',
                        'full_name': table,
                        'xml_element': elem.tag,
                        'xml_attribute': attr_name,
                        'extraction_method': 'xml_attribute'
                    }
            
            # Check element text
            if (elem.text and 
                any(keyword in elem.tag.lower() for keyword in ['table', 'relation']) and
                elem.text.strip() != 'Unknown'):
                
                table = elem.text.strip('[]"`\'')
                tables[table] = {
                    'table': table,
                    'schema': '',
                    'database': '',
                    'full_name': table,
                    'xml_element': elem.tag,
                    'extraction_method': 'xml_element_text'
                }
    
    except ET.ParseError:
        # If XML parsing fails, use regex patterns
        xml_patterns = [
            r'<(?:table|relation)[^>]*>\s*([^<]+)\s*</(?:table|relation)>',
            r'(?:table|relation)\s*=\s*["\']([^"\']+)["\']',
            r'<datasource[^>]*name\s*=\s*["\']([^"\']+)["\']',
            r'connection[^>]*database\s*=\s*["\']([^"\']+)["\']',
            r'<relation[^>]*table\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for i, pattern in enumerate(xml_patterns):
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if match and match != 'Unknown':
                    table = match.strip('[]"`\'')
                    tables[table] = {
                        'table': table,
                        'schema': '',
                        'database': '',
                        'full_name': table,
                        'pattern_match': pattern,
                        'extraction_method': f'xml_pattern_{i+1}'
                    }
    
    return tables

def extract_tables_from_connection_content(content):
    """Extract table information from connection files"""
    tables = {}
    
    # Try JSON first
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            # Look for connection-specific table information
            connection_keys = ['tables', 'relations', 'entities', 'dataSources']
            
            for key in connection_keys:
                if key in data:
                    if isinstance(data[key], list):
                        for item in data[key]:
                            if isinstance(item, dict):
                                table_info = extract_table_from_connection_item(item)
                                if table_info:
                                    tables[table_info['table']] = table_info
                    elif isinstance(data[key], dict):
                        table_info = extract_table_from_connection_item(data[key])
                        if table_info:
                            tables[table_info['table']] = table_info
    except json.JSONDecodeError:
        # Try XML parsing
        try:
            root = ET.fromstring(content)
            for elem in root.iter():
                if any(tag in elem.tag.lower() for tag in ['table', 'relation', 'entity']):
                    table_name = elem.get('name') or elem.text
                    if table_name and table_name != 'Unknown':
                        table = table_name.strip('[]"`\'')
                        tables[table] = {
                            'table': table,
                            'schema': elem.get('schema', ''),
                            'database': elem.get('database', ''),
                            'full_name': table,
                            'extraction_method': 'connection_xml'
                        }
        except ET.ParseError:
            # Pattern-based extraction as fallback
            connection_patterns = [
                r'table["\s]*[:=]["\s]*([^"\';\s]+)',
                r'relation["\s]*[:=]["\s]*([^"\';\s]+)',
                r'FROM\s+([^\s;]+)',
            ]
            
            for pattern in connection_patterns:
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match and match != 'Unknown':
                        table = match.strip('[]"`\'')
                        tables[table] = {
                            'table': table,
                            'schema': '',
                            'database': '',
                            'full_name': table,
                            'extraction_method': 'connection_pattern'
                        }
    
    return tables

def extract_table_from_connection_item(item):
    """Extract table information from a connection item"""
    if not isinstance(item, dict):
        return None
    
    table = (
        item.get('table') or 
        item.get('name') or 
        item.get('tableName') or 
        item.get('relation') or 
        ''
    ).strip()
    
    if not table or table == 'Unknown':
        return None
    
    table = table.strip('[]"`\'')
    schema = item.get('schema', '').strip()
    database = item.get('database', '').strip()
    
    name_parts = [part for part in [database, schema, table] if part]
    full_name = '.'.join(name_parts)
    
    return {
        'table': table,
        'schema': schema,
        'database': database,
        'full_name': full_name,
        'extraction_method': 'connection_item'
    }

def determine_database_type_from_class(db_class):
    """Determine database type from connection class"""
    if not db_class:
        return 'Unknown'
    
    db_class_lower = db_class.lower()
    
    db_type_mappings = {
        'oracle': 'Oracle',
        'sqlserver': 'SQL Server',
        'postgres': 'PostgreSQL',
        'mysql': 'MySQL',
        'teradata': 'Teradata',
        'snowflake': 'Snowflake',
        'redshift': 'Redshift',
        'bigquery': 'BigQuery',
        'databricks': 'Databricks',
        'sybase': 'Sybase',
        'db2': 'DB2',
    }
    
    for key, db_type in db_type_mappings.items():
        if key in db_class_lower:
            return db_type
    
    return 'Other'

def export_table_mappings_to_csv(table_mappings, output_file, extraction_stats):
    """Export table mappings to CSV file with comprehensive information"""
    try:
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Table Name', 'Schema', 'Database', 'Server', 'Full Name', 
                'Database Type', 'Node Name', 'Node ID', 'Connection Class',
                'Extraction Method', 'Additional Info'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            
            writer.writeheader()
            
            # Sort by database type, then schema, then table
            sorted_tables = sorted(
                table_mappings.items(),
                key=lambda x: (
                    x[1].get('database_type', 'ZZZ'),
                    x[1].get('schema', 'ZZZ'),
                    x[1].get('table', 'ZZZ')
                )
            )
            
            for table_key, table_info in sorted_tables:
                # Compile additional info
                additional_info = []
                if 'pattern_match' in table_info:
                    additional_info.append(f"Pattern: {table_info['pattern_match'][:50]}")
                if 'xml_element' in table_info:
                    additional_info.append(f"XML Element: {table_info['xml_element']}")
                if 'json_path' in table_info:
                    additional_info.append(f"JSON Path: {table_info['json_path']}")
                
                writer.writerow({
                    'Table Name': table_info.get('table', ''),
                    'Schema': table_info.get('schema', ''),
                    'Database': table_info.get('database', ''),
                    'Server': table_info.get('server', ''),
                    'Full Name': table_info.get('full_name', ''),
                    'Database Type': table_info.get('database_type', ''),
                    'Node Name': table_info.get('node_name', ''),
                    'Node ID': table_info.get('node_id', ''),
                    'Connection Class': table_info.get('connection_class', ''),
                    'Extraction Method': table_info.get('extraction_method', ''),
                    'Additional Info': " | ".join(additional_info)
                })
        
        print(f"✅ Table mappings exported to: {output_file}")
        
        # Create summary file
        summary_file = output_file.replace('.csv', '_summary.csv')
        create_table_summary(table_mappings, summary_file, extraction_stats)
        
    except Exception as e:
        print(f"❌ Error writing CSV file: {e}")

def create_table_summary(table_mappings, summary_file, extraction_stats):
    """Create a summary analysis of the extracted tables"""
    try:
        # Analyze by database type
        db_type_summary = defaultdict(lambda: {
            'count': 0,
            'tables': set(),
            'schemas': set(),
            'databases': set()
        })
        
        # Analyze by extraction method
        method_summary = defaultdict(int)
        
        for table_info in table_mappings.values():
            db_type = table_info.get('database_type', 'Unknown')
            method = table_info.get('extraction_method', 'Unknown')
            
            db_type_summary[db_type]['count'] += 1
            db_type_summary[db_type]['tables'].add(table_info.get('table', ''))
            if table_info.get('schema'):
                db_type_summary[db_type]['schemas'].add(table_info['schema'])
            if table_info.get('database'):
                db_type_summary[db_type]['databases'].add(table_info['database'])
            
            method_summary[method] += 1
        
        with open(summary_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Database type summary
            writer.writerow(['=== DATABASE TYPE SUMMARY ==='])
            writer.writerow(['Database Type', 'Table Count', 'Unique Schemas', 'Unique Databases'])
            
            for db_type, summary in sorted(db_type_summary.items(), key=lambda x: x[1]['count'], reverse=True):
                writer.writerow([
                    db_type,
                    summary['count'],
                    len(summary['schemas']),
                    len(summary['databases'])
                ])
            
            writer.writerow([])  # Empty row
            
            # Extraction method summary
            writer.writerow(['=== EXTRACTION METHOD SUMMARY ==='])
            writer.writerow(['Extraction Method', 'Count', 'Percentage'])
            
            total_extractions = sum(method_summary.values())
            for method, count in sorted(method_summary.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / total_extractions * 100) if total_extractions > 0 else 0
                writer.writerow([method, count, f"{percentage:.1f}%"])
            
            writer.writerow([])  # Empty row
            
            # Overall statistics
            writer.writerow(['=== OVERALL STATISTICS ==='])
            writer.writerow(['Metric', 'Value'])
            writer.writerow(['Total Tables Found', len(table_mappings)])
            writer.writerow(['JSON Extractions', extraction_stats['json_extractions']])
            writer.writerow(['XML Extractions', extraction_stats['xml_extractions']])
            writer.writerow(['Connection Extractions', extraction_stats['connection_extractions']])
            writer.writerow(['Pattern Extractions', extraction_stats['pattern_extractions']])
        
        print(f"✅ Summary analysis written to: {summary_file}")
        
    except Exception as e:
        print(f"❌ Error creating summary: {e}")

def main():
    """Main function with comprehensive interactive interface"""
    try:
        file_path, output_csv = get_user_inputs()
        
        print(f"🚀 Starting comprehensive table mapping extraction...")
        table_mappings, extraction_stats = extract_table_mappings(file_path)
        
        if table_mappings:
            print(f"\n📊 EXTRACTION RESULTS")
            print(f"{'='*60}")
            print(f"✅ Found {len(table_mappings)} table mappings")
            
            # Group results by database type for display
            by_db_type = defaultdict(list)
            for table_key, table_info in table_mappings.items():
                db_type = table_info.get('database_type', 'Unknown')
                by_db_type[db_type].append(table_info)
            
            # Display summary by database type
            for db_type, tables in sorted(by_db_type.items(), key=lambda x: len(x[1]), reverse=True):
                print(f"\n🗄️ {db_type} ({len(tables)} tables):")
                
                # Show first few tables as examples
                for table_info in sorted(tables, key=lambda x: x['full_name'])[:5]:
                    full_name = table_info['full_name']
                    method = table_info['extraction_method']
                    node_name = table_info.get('node_name', 'N/A')
                    
                    print(f"  📋 {full_name}")
                    print(f"      Method: {method} | Node: {node_name}")
                
                if len(tables) > 5:
                    print(f"      ... and {len(tables) - 5} more")
            
            # Show extraction method breakdown
            method_counts = defaultdict(int)
            for table_info in table_mappings.values():
                method_counts[table_info.get('extraction_method', 'Unknown')] += 1
            
            print(f"\n🔍 Extraction method breakdown:")
            for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
                percentage = (count / len(table_mappings) * 100) if table_mappings else 0
                print(f"  {method}: {count} tables ({percentage:.1f}%)")
            
            # Export to CSV if requested
            if output_csv:
                export_table_mappings_to_csv(table_mappings, output_csv, extraction_stats)
            
            # Show unique table names
            unique_tables = set(info['table'] for info in table_mappings.values())
            print(f"\n📋 Table analysis:")
            print(f"  Unique table names: {len(unique_tables)}")
            
            # Show schema/database distribution
            unique_schemas = set(info['schema'] for info in table_mappings.values() if info.get('schema'))
            unique_databases = set(info['database'] for info in table_mappings.values() if info.get('database'))
            
            if unique_schemas:
                print(f"  Unique schemas: {len(unique_schemas)}")
            if unique_databases:
                print(f"  Unique databases: {len(unique_databases)}")
            
        else:
            print("\n❌ No table mappings found in the file")
            print("   This could mean:")
            print("   • The flow file doesn't contain database connections")
            print("   • Tables are referenced in a format not recognized")
            print("   • The file structure is different than expected")
        
        print(f"\n🎉 Basic table mapping extraction complete!")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Extraction interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during extraction: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()