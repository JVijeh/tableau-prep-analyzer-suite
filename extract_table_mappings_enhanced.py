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
    print("=== Table Mapping Extraction - Enhanced Version ===")
    print("Comprehensive extraction with advanced pattern recognition and relationship mapping")
    print()
    
    # Get input file
    while True:
        file_path = input("Enter the path to the .tfl or .tflx file: ").strip()
        if os.path.exists(file_path):
            break
        print(f"Error: File '{file_path}' does not exist. Please try again.")
    
    # Get output options
    output_csv = input("Enter output CSV file name (press Enter to skip CSV export): ").strip()
    if output_csv and not output_csv.endswith('.csv'):
        output_csv += '.csv'
    
    # Analysis depth
    print("\nAnalysis depth options:")
    print("1. Standard extraction")
    print("2. Deep analysis (includes relationship mapping and metadata)")
    
    while True:
        depth_choice = input("Enter your choice (1-2): ").strip()
        if depth_choice in ['1', '2']:
            deep_analysis = depth_choice == '2'
            break
        print("Invalid choice. Please enter 1 or 2.")
    
    return file_path, output_csv, deep_analysis

def extract_comprehensive_table_mappings(file_path, deep_analysis=False):
    """Extract comprehensive table mappings using enhanced logic with relationship tracking"""
    table_mappings = {}
    node_relationships = {}
    metadata = {}
    extraction_stats = {
        'json_extractions': 0,
        'xml_extractions': 0,
        'pattern_extractions': 0,
        'connection_extractions': 0,
        'sql_extractions': 0,
        'relationship_mappings': 0
    }
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        print(f"\n🚀 Starting enhanced table mapping extraction...")
        print(f"📁 File: {file_path}")
        print(f"🔍 Deep analysis: {'Enabled' if deep_analysis else 'Disabled'}")
        
        if file_path.endswith('.tfl'):
            # Direct JSON file
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                extracted = extract_enhanced_tables_from_json_content(
                    content, node_relationships, metadata, deep_analysis
                )
                table_mappings.update(extracted)
                extraction_stats['json_extractions'] += len(extracted)
                
        elif file_path.endswith('.tflx'):
            # ZIP archive - comprehensive extraction
            with zipfile.ZipFile(file_path, 'r') as zf:
                zf.extractall(temp_dir)
                
                print("  📁 Analyzing archive contents...")
                
                # Get comprehensive file list
                all_files = []
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path_full = os.path.join(root, file)
                        rel_path = os.path.relpath(file_path_full, temp_dir)
                        all_files.append((file_path_full, rel_path, file))
                
                # Process files by priority
                file_priorities = {
                    'flow': 1,
                    'json': 2,
                    'xml': 3,
                    'connection': 4,
                    'other': 5
                }
                
                def get_file_priority(filename):
                    if filename.lower() in ['flow', 'flow.json']:
                        return file_priorities['flow']
                    elif filename.endswith('.json'):
                        return file_priorities['json']
                    elif filename.endswith(('.xml', '.twb', '.tds')):
                        return file_priorities['xml']
                    elif any(keyword in filename.lower() for keyword in ['connection', 'datasource']):
                        return file_priorities['connection']
                    else:
                        return file_priorities['other']
                
                # Sort files by priority
                all_files.sort(key=lambda x: get_file_priority(x[2]))
                
                # Process each file
                for file_path_full, rel_path, filename in all_files:
                    try:
                        if get_file_priority(filename) <= file_priorities['connection']:
                            print(f"    📄 Processing: {rel_path}")
                            
                            with open(file_path_full, 'r', encoding='utf-8') as f:
                                content = f.read()
                            
                            if filename.lower() in ['flow', 'flow.json'] or filename.endswith('.json'):
                                extracted = extract_enhanced_tables_from_json_content(
                                    content, node_relationships, metadata, deep_analysis
                                )
                                table_mappings.update(extracted)
                                extraction_stats['json_extractions'] += len(extracted)
                            
                            elif filename.endswith(('.xml', '.twb', '.tds')):
                                extracted = extract_enhanced_tables_from_xml_content(content, deep_analysis)
                                table_mappings.update(extracted)
                                extraction_stats['xml_extractions'] += len(extracted)
                            
                            elif any(keyword in filename.lower() for keyword in ['connection', 'datasource']):
                                extracted = extract_enhanced_tables_from_connection_content(content, deep_analysis)
                                table_mappings.update(extracted)
                                extraction_stats['connection_extractions'] += len(extracted)
                    
                    except Exception as e:
                        print(f"      ⚠️ Could not process {rel_path}: {e}")
                        continue
                
                # Deep analysis: extract metadata and relationships
                if deep_analysis:
                    print("  🔍 Performing deep analysis...")
                    extract_enhanced_metadata(temp_dir, metadata)
                    build_table_relationships(table_mappings, node_relationships)
                    extraction_stats['relationship_mappings'] = len(node_relationships)
        
        # Enhance table mappings with metadata
        if deep_analysis and metadata:
            enhance_table_mappings_with_metadata(table_mappings, metadata)
        
        print(f"\n📊 Enhanced extraction summary:")
        for stat_name, count in extraction_stats.items():
            if count > 0:
                print(f"  {stat_name.replace('_', ' ').title()}: {count}")
        print(f"  Total unique tables: {len(table_mappings)}")
        
    except Exception as e:
        print(f"❌ Error processing file: {e}")
        import traceback
        traceback.print_exc()
    
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
    
    result = {
        'table_mappings': table_mappings,
        'node_relationships': node_relationships,
        'metadata': metadata if deep_analysis else {},
        'extraction_stats': extraction_stats
    }
    
    return result

def extract_enhanced_tables_from_json_content(content, node_relationships, metadata, deep_analysis):
    """Enhanced table extraction from JSON with comprehensive analysis"""
    table_mappings = {}
    
    try:
        data = json.loads(content)
        
        # Enhanced node processing
        if 'nodes' in data and isinstance(data['nodes'], dict):
            for node_id, node in data['nodes'].items():
                extracted_tables = extract_enhanced_tables_from_node(
                    node, node_id, node_relationships, deep_analysis
                )
                table_mappings.update(extracted_tables)
        
        # Enhanced connection processing
        if 'connections' in data and isinstance(data['connections'], dict):
            for conn_id, conn_info in data['connections'].items():
                extracted_tables = extract_enhanced_tables_from_connection(
                    conn_info, conn_id, deep_analysis
                )
                table_mappings.update(extracted_tables)
        
        # Deep analysis: Look for SQL queries and custom connections
        if deep_analysis:
            sql_tables = extract_tables_from_sql_queries(data)
            table_mappings.update(sql_tables)
            
            # Extract metadata for enhancement
            extract_flow_metadata(data, metadata)
        
        # Enhanced recursive search
        recursive_tables = extract_tables_from_json_recursive_enhanced(data, deep_analysis)
        table_mappings.update(recursive_tables)
        
    except json.JSONDecodeError:
        # Enhanced pattern-based extraction
        pattern_tables = extract_tables_from_enhanced_text_patterns(content, deep_analysis)
        table_mappings.update(pattern_tables)
    
    return table_mappings

def extract_enhanced_tables_from_node(node, node_id, node_relationships, deep_analysis):
    """Enhanced table extraction from flow node with relationship tracking"""
    tables = {}
    
    if not isinstance(node, dict):
        return tables
    
    node_name = node.get('name', f'Node_{node_id}')
    node_type = node.get('nodeType', 'unknown')
    
    # Store node relationship info for deep analysis
    if deep_analysis:
        node_relationships[node_id] = {
            'name': node_name,
            'type': node_type,
            'tables': [],
            'inputs': node.get('inputs', {}),
            'parent_nodes': []
        }
    
    # Enhanced relation processing
    if 'relation' in node:
        relation = node['relation']
        if isinstance(relation, dict):
            table_info = extract_enhanced_table_from_relation(relation, node_name, node_id, deep_analysis)
            if table_info:
                table_key = table_info['table']
                tables[table_key] = table_info
                
                if deep_analysis and node_id in node_relationships:
                    node_relationships[node_id]['tables'].append(table_key)
    
    # Enhanced connection attributes processing
    if 'connectionAttributes' in node:
        conn_attrs = node['connectionAttributes']
        if isinstance(conn_attrs, dict):
            table_info = extract_enhanced_table_from_connection_attributes(
                conn_attrs, node_name, node_id, deep_analysis
            )
            if table_info:
                table_key = table_info['table']
                tables[table_key] = table_info
                
                if deep_analysis and node_id in node_relationships:
                    node_relationships[node_id]['tables'].append(table_key)
    
    # Process nested containers
    if 'loomContainer' in node:
        loom_container = node['loomContainer']
        if isinstance(loom_container, dict) and 'nodes' in loom_container:
            for sub_node_id, sub_node in loom_container['nodes'].items():
                sub_tables = extract_enhanced_tables_from_node(
                    sub_node, sub_node_id, node_relationships, deep_analysis
                )
                tables.update(sub_tables)
                
                # Track parent-child relationships
                if deep_analysis and sub_node_id in node_relationships:
                    node_relationships[sub_node_id]['parent_nodes'].append(node_id)
    
    return tables

def extract_enhanced_tables_from_connection(conn_info, conn_id, deep_analysis):
    """Enhanced table extraction from connection definition with metadata"""
    tables = {}
    
    if not isinstance(conn_info, dict):
        return tables
    
    # Enhanced table name extraction with multiple attributes
    table_attrs = ['table', 'relation', 'tableName', 'relationName', 'defaultTable', 'entity']
    table = ''
    
    for attr in table_attrs:
        if attr in conn_info and conn_info[attr]:
            table = clean_table_name(conn_info[attr])
            break
    
    if not table or table == 'Unknown':
        return tables
    
    # Enhanced component extraction
    schema = get_first_valid_attr(conn_info, ['schema', 'owner', 'schemaName'])
    database = get_first_valid_attr(conn_info, ['database', 'dbname', 'databaseName', 'catalog'])
    server = get_first_valid_attr(conn_info, ['server', 'hostname', 'host', 'serverName'])
    port = conn_info.get('port', '').strip()
    
    # Enhanced database type detection
    db_class = conn_info.get('class', '').lower()
    db_type = determine_enhanced_database_type_from_class(db_class)
    
    # Build enhanced full name
    name_components = [comp for comp in [server, database, schema, table] if comp]
    full_name = '.'.join(name_components)
    
    # Create enhanced table information
    table_info = {
        'table': table,
        'schema': schema,
        'database': database,
        'server': server,
        'port': port,
        'full_name': full_name,
        'database_type': db_type,
        'connection_class': db_class,
        'connection_id': conn_id,
        'extraction_method': 'enhanced_connection_definition'
    }
    
    # Deep analysis: extract comprehensive connection metadata
    if deep_analysis:
        table_info.update({
            'connection_properties': {
                k: v for k, v in conn_info.items() 
                if k not in ['table', 'schema', 'database', 'server', 'port']
            },
            'authentication_method': conn_info.get('authentication', 'unknown'),
            'connection_timeout': conn_info.get('timeout', ''),
            'ssl_enabled': conn_info.get('sslmode', '').lower() in ['require', 'true', 'enabled']
        })
    
    tables[table] = table_info
    return tables

def extract_enhanced_table_from_relation(relation, node_name, node_id, deep_analysis):
    """Enhanced table extraction from relation with metadata tracking"""
    table = relation.get('table', '').strip()
    
    if not table or table == 'Unknown':
        return None
    
    # Enhanced table name cleaning
    table = clean_table_name(table)
    
    schema = relation.get('schema', '').strip()
    database = relation.get('database', '').strip()
    catalog = relation.get('catalog', '').strip()
    
    # Enhanced component extraction
    server = relation.get('server', relation.get('hostname', relation.get('host', ''))).strip()
    port = relation.get('port', '').strip()
    
    # Build enhanced full name
    name_components = [comp for comp in [catalog, database, schema, table] if comp]
    full_name = '.'.join(name_components)
    
    # Enhanced metadata extraction
    table_info = {
        'table': table,
        'schema': schema,
        'database': database,
        'catalog': catalog,
        'server': server,
        'port': port,
        'full_name': full_name,
        'node_name': node_name,
        'node_id': node_id,
        'extraction_method': 'enhanced_relation_structure'
    }
    
    # Deep analysis: extract additional metadata
    if deep_analysis:
        table_info.update({
            'column_count': len(relation.get('columns', {})),
            'has_keys': bool(relation.get('keys')),
            'relation_type': relation.get('type', ''),
            'connection_info': {
                k: v for k, v in relation.items() 
                if k not in ['table', 'schema', 'database', 'columns']
            }
        })
    
    return table_info

def extract_enhanced_table_from_connection_attributes(conn_attrs, node_name, node_id, deep_analysis):
    """Enhanced table extraction from connection attributes with comprehensive metadata"""
    # Multiple attribute names for table
    table_attrs = ['table', 'relation', 'tableName', 'relationName', 'defaultTable']
    table = ''
    
    for attr in table_attrs:
        if attr in conn_attrs and conn_attrs[attr]:
            table = conn_attrs[attr].strip()
            break
    
    if not table or table == 'Unknown':
        return None
    
    # Enhanced table name cleaning
    table = clean_table_name(table)
    
    # Enhanced component extraction with multiple attribute names
    schema_attrs = ['schema', 'owner', 'schemaName']
    database_attrs = ['database', 'dbname', 'databaseName', 'catalog']
    server_attrs = ['server', 'hostname', 'host', 'serverName']
    
    schema = get_first_valid_attr(conn_attrs, schema_attrs)
    database = get_first_valid_attr(conn_attrs, database_attrs)
    server = get_first_valid_attr(conn_attrs, server_attrs)
    
    port = conn_attrs.get('port', '').strip()
    
    # Enhanced database type detection
    db_class = conn_attrs.get('class', '').lower()
    db_type = determine_enhanced_database_type_from_class(db_class)
    
    # Build enhanced full name
    name_components = [comp for comp in [server, database, schema, table] if comp]
    full_name = '.'.join(name_components)
    
    # Enhanced table information
    table_info = {
        'table': table,
        'schema': schema,
        'database': database,
        'server': server,
        'port': port,
        'full_name': full_name,
        'database_type': db_type,
        'connection_class': db_class,
        'node_name': node_name,
        'node_id': node_id,
        'extraction_method': 'enhanced_connection_attributes'
    }
    
    # Deep analysis: extract comprehensive connection metadata
    if deep_analysis:
        table_info.update({
            'connection_string': build_connection_string(conn_attrs),
            'authentication_method': conn_attrs.get('authentication', 'unknown'),
            'ssl_enabled': conn_attrs.get('sslmode', '').lower() in ['require', 'true', 'enabled'],
            'connection_timeout': conn_attrs.get('timeout', ''),
            'additional_properties': {
                k: v for k, v in conn_attrs.items() 
                if k not in ['table', 'schema', 'database', 'server', 'port', 'class']
            }
        })
    
    return table_info

def extract_tables_from_sql_queries(data):
    """Extract table references from embedded SQL queries"""
    tables = {}
    
    def search_for_sql(obj, path=""):
        if isinstance(obj, dict):
            for key, value in obj.items():
                if isinstance(value, str) and is_sql_query(value):
                    sql_tables = parse_sql_for_tables(value, f"{path}.{key}")
                    tables.update(sql_tables)
                elif isinstance(value, (dict, list)):
                    search_for_sql(value, f"{path}.{key}")
        elif isinstance(obj, list):
            for i, item in enumerate(obj):
                if isinstance(item, (dict, list)):
                    search_for_sql(item, f"{path}[{i}]")
    
    search_for_sql(data)
    return tables

def extract_flow_metadata(data, metadata):
    """Extract flow-level metadata for enhanced analysis"""
    if not isinstance(data, dict):
        return
    
    # Extract flow-level information
    if 'flowInfo' in data:
        flow_info = data['flowInfo']
        if isinstance(flow_info, dict):
            metadata['flow_info'] = {
                'name': flow_info.get('name', ''),
                'version': flow_info.get('version', ''),
                'created': flow_info.get('created', ''),
                'modified': flow_info.get('modified', ''),
                'author': flow_info.get('author', '')
            }
    
    # Extract connection metadata
    if 'connections' in data:
        connections = data['connections']
        if isinstance(connections, dict):
            metadata['connection_summary'] = {
                'total_connections': len(connections),
                'connection_types': []
            }
            
            for conn_id, conn_info in connections.items():
                if isinstance(conn_info, dict):
                    conn_type = conn_info.get('class', 'unknown')
                    metadata['connection_summary']['connection_types'].append(conn_type)
    
    # Extract node summary
    if 'nodes' in data:
        nodes = data['nodes']
        if isinstance(nodes, dict):
            node_types = defaultdict(int)
            for node in nodes.values():
                if isinstance(node, dict):
                    node_type = node.get('nodeType', 'unknown')
                    node_types[node_type] += 1
            
            metadata['node_summary'] = {
                'total_nodes': len(nodes),
                'node_types': dict(node_types)
            }
    
    # Extract field statistics
    total_fields = 0
    calculated_fields = 0
    
    def count_fields_recursive(obj):
        nonlocal total_fields, calculated_fields
        
        if isinstance(obj, dict):
            if 'fields' in obj:
                fields = obj['fields']
                if isinstance(fields, dict):
                    total_fields += len(fields)
                    for field_info in fields.values():
                        if isinstance(field_info, dict) and field_info.get('calc'):
                            calculated_fields += 1
            
            for value in obj.values():
                if isinstance(value, (dict, list)):
                    count_fields_recursive(value)
        
        elif isinstance(obj, list):
            for item in obj:
                if isinstance(item, (dict, list)):
                    count_fields_recursive(item)
    
    count_fields_recursive(data)
    
    metadata['field_summary'] = {
        'total_fields': total_fields,
        'calculated_fields': calculated_fields
    }

def is_sql_query(text):
    """Determine if text contains SQL queries"""
    sql_keywords = ['SELECT', 'FROM', 'WHERE', 'JOIN', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP']
    text_upper = text.upper()
    return any(keyword in text_upper for keyword in sql_keywords) and len(text) > 20

def parse_sql_for_tables(sql, context):
    """Parse SQL query to extract table references"""
    tables = {}
    
    # Enhanced SQL parsing patterns
    sql_patterns = [
        r'\bFROM\s+([^\s,()]+(?:\s*,\s*[^\s,()]+)*)',
        r'\bJOIN\s+([^\s,()]+)',
        r'\bINTO\s+([^\s,()]+)',
        r'\bUPDATE\s+([^\s,()]+)',
        r'\bTABLE\s+([^\s,()]+)',
    ]
    
    for pattern in sql_patterns:
        matches = re.findall(pattern, sql, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            # Handle multiple tables separated by commas
            table_list = [t.strip() for t in match.split(',')]
            
            for table_ref in table_list:
                if table_ref and not table_ref.upper() in ['SELECT', 'FROM', 'WHERE']:
                    table = clean_table_name(table_ref)
                    
                    # Parse qualified table names
                    if '.' in table:
                        parts = table.split('.')
                        if len(parts) >= 2:
                            schema = parts[-2] if len(parts) > 1 else ''
                            table_name = parts[-1]
                            database = parts[-3] if len(parts) > 2 else ''
                        else:
                            table_name = table
                            schema = database = ''
                    else:
                        table_name = table
                        schema = database = ''
                    
                    tables[table_name] = {
                        'table': table_name,
                        'schema': schema,
                        'database': database,
                        'full_name': table,
                        'sql_context': context,
                        'extraction_method': 'sql_query_analysis'
                    }
    
    return tables

def extract_enhanced_tables_from_xml_content(content, deep_analysis):
    """Enhanced XML extraction with namespace awareness and deep analysis"""
    tables = {}
    
    try:
        # Try parsing with namespace awareness
        root = ET.fromstring(content)
        
        # Extract with enhanced element processing
        for elem in root.iter():
            table_info = extract_table_from_xml_element_enhanced(elem, deep_analysis)
            if table_info:
                tables[table_info['table']] = table_info
        
    except ET.ParseError:
        # Enhanced regex patterns for malformed XML
        xml_patterns = [
            r'<(?:table|relation)[^>]*name\s*=\s*["\']([^"\']+)["\'][^>]*>',
            r'<(?:table|relation)[^>]*>\s*([^<]+)\s*</(?:table|relation)>',
            r'(?:table|relation)\s*=\s*["\']([^"\']+)["\']',
            r'<datasource[^>]*name\s*=\s*["\']([^"\']+)["\']',
            r'<connection[^>]*table\s*=\s*["\']([^"\']+)["\']',
            r'<relation[^>]*table\s*=\s*["\']([^"\']+)["\'][^>]*/>',
            r'table\s*=\s*["\']([^"\']+)["\']',
        ]
        
        for i, pattern in enumerate(xml_patterns):
            matches = re.findall(pattern, content, re.IGNORECASE | re.DOTALL)
            for match in matches:
                if match and match != 'Unknown':
                    table = clean_table_name(match)
                    
                    table_info = {
                        'table': table,
                        'schema': '',
                        'database': '',
                        'full_name': table,
                        'pattern_match': pattern,
                        'extraction_method': f'enhanced_xml_pattern_{i+1}'
                    }
                    
                    if deep_analysis:
                        table_info['xml_context'] = extract_xml_context(content, match)
                    
                    tables[table] = table_info
    
    return tables

def extract_table_from_xml_element_enhanced(elem, deep_analysis):
    """Enhanced table extraction from XML element with metadata"""
    table_info = None
    
    # Check element attributes for table information
    table_attrs = ['name', 'table', 'relation', 'tableName']
    
    for attr in table_attrs:
        if attr in elem.attrib:
            table = clean_table_name(elem.attrib[attr])
            if table and table != 'Unknown':
                table_info = {
                    'table': table,
                    'schema': elem.attrib.get('schema', ''),
                    'database': elem.attrib.get('database', ''),
                    'full_name': table,
                    'xml_element': elem.tag,
                    'xml_attribute': attr,
                    'extraction_method': 'enhanced_xml_attribute'
                }
                break
    
    # Check element text if no attribute found
    if not table_info and elem.text:
        text = elem.text.strip()
        if (text and text != 'Unknown' and 
            any(keyword in elem.tag.lower() for keyword in ['table', 'relation'])):
            
            table = clean_table_name(text)
            table_info = {
                'table': table,
                'schema': '',
                'database': '',
                'full_name': table,
                'xml_element': elem.tag,
                'extraction_method': 'enhanced_xml_element_text'
            }
    
    # Deep analysis: extract additional XML metadata
    if table_info and deep_analysis:
        table_info.update({
            'xml_namespace': extract_namespace(elem),
            'xml_attributes': dict(elem.attrib),
            'xml_parent': elem.getparent().tag if elem.getparent() is not None else None,
            'xml_children': [child.tag for child in elem]
        })
    
    return table_info

def extract_enhanced_tables_from_connection_content(content, deep_analysis):
    """Enhanced connection file processing with comprehensive analysis"""
    tables = {}
    
    # Try JSON first
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            # Enhanced connection-specific processing
            connection_sections = [
                'tables', 'relations', 'entities', 'dataSources', 
                'schemas', 'catalogs', 'connections'
            ]
            
            for section in connection_sections:
                if section in data:
                    section_data = data[section]
                    
                    if isinstance(section_data, list):
                        for item in section_data:
                            table_info = extract_enhanced_table_from_connection_item(item, deep_analysis)
                            if table_info:
                                tables[table_info['table']] = table_info
                    
                    elif isinstance(section_data, dict):
                        for key, item in section_data.items():
                            table_info = extract_enhanced_table_from_connection_item(item, deep_analysis)
                            if table_info:
                                table_info['connection_key'] = key
                                tables[table_info['table']] = table_info
    
    except json.JSONDecodeError:
        # Enhanced XML processing for connection files
        try:
            root = ET.fromstring(content)
            
            # Look for connection-specific XML structures
            connection_elements = ['table', 'relation', 'entity', 'datasource']
            
            for elem_name in connection_elements:
                for elem in root.iter(elem_name):
                    table_info = extract_table_from_xml_element_enhanced(elem, deep_analysis)
                    if table_info:
                        table_info['extraction_method'] = 'enhanced_connection_xml'
                        tables[table_info['table']] = table_info
        
        except ET.ParseError:
            # Enhanced pattern-based extraction for connection files
            connection_patterns = [
                r'table["\s]*[:=]["\s]*([^"\';\s]+)',
                r'relation["\s]*[:=]["\s]*([^"\';\s]+)',
                r'tableName["\s]*[:=]["\s]*([^"\';\s]+)',
                r'FROM\s+([^\s;]+)',
                r'SELECT\s+\*\s+FROM\s+([^\s;]+)',
            ]
            
            for i, pattern in enumerate(connection_patterns):
                matches = re.findall(pattern, content, re.IGNORECASE)
                for match in matches:
                    if match and match != 'Unknown':
                        table = clean_table_name(match)
                        tables[table] = {
                            'table': table,
                            'schema': '',
                            'database': '',
                            'full_name': table,
                            'pattern_match': pattern,
                            'extraction_method': f'enhanced_connection_pattern_{i+1}'
                        }
    
    return tables

def extract_enhanced_table_from_connection_item(item, deep_analysis):
    """Enhanced table extraction from connection item with metadata"""
    if not isinstance(item, dict):
        return None
    
    # Enhanced table name extraction
    table_keys = ['table', 'name', 'tableName', 'relation', 'relationName', 'entity']
    table = ''
    
    for key in table_keys:
        if key in item and item[key]:
            table = clean_table_name(item[key])
            break
    
    if not table or table == 'Unknown':
        return None
    
    # Enhanced component extraction
    schema = get_first_valid_attr(item, ['schema', 'owner', 'schemaName'])
    database = get_first_valid_attr(item, ['database', 'dbname', 'databaseName', 'catalog'])
    server = get_first_valid_attr(item, ['server', 'hostname', 'host', 'serverName'])
    
    # Build full name
    name_components = [comp for comp in [server, database, schema, table] if comp]
    full_name = '.'.join(name_components)
    
    # Enhanced table information
    table_info = {
        'table': table,
        'schema': schema,
        'database': database,
        'server': server,
        'full_name': full_name,
        'extraction_method': 'enhanced_connection_item'
    }
    
    # Deep analysis: extract comprehensive metadata
    if deep_analysis:
        table_info.update({
            'item_type': item.get('type', ''),
            'item_id': item.get('id', ''),
            'created_date': item.get('created', ''),
            'modified_date': item.get('modified', ''),
            'permissions': item.get('permissions', []),
            'tags': item.get('tags', []),
            'description': item.get('description', ''),
            'additional_metadata': {
                k: v for k, v in item.items() 
                if k not in ['table', 'name', 'schema', 'database', 'server']
            }
        })
    
    return table_info

# Helper functions

def clean_table_name(table):
    """Clean and normalize table name"""
    if not table:
        return ''
    
    # Remove common delimiters and quotes
    table = table.strip('[]"`\'(){}')
    
    # Remove SQL keywords if they somehow got included
    sql_keywords = ['FROM', 'JOIN', 'WHERE', 'SELECT', 'UPDATE', 'INSERT', 'DELETE']
    for keyword in sql_keywords:
        if table.upper() == keyword:
            return ''
    
    return table.strip()

def get_first_valid_attr(obj, attr_list):
    """Get first valid attribute from a list of possible attribute names"""
    for attr in attr_list:
        if attr in obj and obj[attr]:
            return obj[attr].strip()
    return ''

def determine_enhanced_database_type_from_class(db_class):
    """Enhanced database type determination with comprehensive mappings"""
    if not db_class:
        return 'Unknown'
    
    db_class_lower = db_class.lower()
    
    # Comprehensive database type mappings
    db_type_mappings = {
        'oracle': 'Oracle',
        'sqlserver': 'SQL Server',
        'mssql': 'SQL Server',
        'postgres': 'PostgreSQL',
        'postgresql': 'PostgreSQL',
        'mysql': 'MySQL',
        'mariadb': 'MySQL',
        'teradata': 'Teradata',
        'snowflake': 'Snowflake',
        'redshift': 'Redshift',
        'bigquery': 'BigQuery',
        'databricks': 'Databricks',
        'sybase': 'Sybase',
        'db2': 'DB2',
        'informix': 'Informix',
        'access': 'Access',
        'sqlite': 'SQLite',
        'vertica': 'Vertica',
        'hive': 'Apache Hive',
        'spark': 'Apache Spark',
        'cassandra': 'Cassandra',
        'mongodb': 'MongoDB',
        'dynamodb': 'DynamoDB'
    }
    
    for key, db_type in db_type_mappings.items():
        if key in db_class_lower:
            return db_type
    
    # Check for JDBC/ODBC patterns
    if 'jdbc' in db_class_lower:
        return 'JDBC Connection'
    elif 'odbc' in db_class_lower:
        return 'ODBC Connection'
    
    return 'Other'

def build_connection_string(conn_attrs):
    """Build a connection string from connection attributes"""
    components = []
    
    server = conn_attrs.get('server', conn_attrs.get('hostname', ''))
    port = conn_attrs.get('port', '')
    database = conn_attrs.get('database', conn_attrs.get('dbname', ''))
    
    if server:
        if port:
            components.append(f"{server}:{port}")
        else:
            components.append(server)
    
    if database:
        components.append(f"database={database}")
    
    return ';'.join(components) if components else ''

def extract_namespace(elem):
    """Extract XML namespace from element"""
    if elem.tag.startswith('{'):
        return elem.tag[1:elem.tag.find('}')]
    return ''

def extract_xml_context(content, match):
    """Extract surrounding XML context for a match"""
    try:
        # Find the match in the content and extract surrounding context
        match_index = content.find(match)
        if match_index != -1:
            start = max(0, match_index - 100)
            end = min(len(content), match_index + len(match) + 100)
            return content[start:end].strip()
    except:
        pass
    return ''

def extract_enhanced_metadata(temp_dir, metadata):
    """Extract enhanced metadata from all files in the archive"""
    metadata['file_structure'] = []
    metadata['connections'] = []
    metadata['schemas'] = set()
    metadata['databases'] = set()
    
    for root, dirs, files in os.walk(temp_dir):
        for file in files:
            file_path = os.path.join(root, file)
            rel_path = os.path.relpath(file_path, temp_dir)
            
            metadata['file_structure'].append({
                'path': rel_path,
                'size': os.path.getsize(file_path),
                'type': get_file_type(file)
            })
            
            # Extract connection metadata
            if any(keyword in file.lower() for keyword in ['connection', 'datasource']):
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read()
                        conn_metadata = extract_connection_metadata(content)
                        if conn_metadata:
                            metadata['connections'].append(conn_metadata)
                except:
                    pass

def extract_connection_metadata(content):
    """Extract metadata from connection content"""
    metadata = {}
    
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            metadata = {
                'type': data.get('type', ''),
                'class': data.get('class', ''),
                'server': data.get('server', ''),
                'database': data.get('database', ''),
                'properties': list(data.keys())
            }
    except:
        # Try to extract basic info with regex
        patterns = {
            'server': r'server["\s]*[:=]["\s]*([^"\';\s]+)',
            'database': r'database["\s]*[:=]["\s]*([^"\';\s]+)',
            'class': r'class["\s]*[:=]["\s]*([^"\';\s]+)'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                metadata[key] = match.group(1)
    
    return metadata

def get_file_type(filename):
    """Determine file type from filename"""
    if filename.endswith('.json'):
        return 'JSON'
    elif filename.endswith('.xml'):
        return 'XML'
    elif filename.endswith(('.twb', '.tds')):
        return 'Tableau'
    elif filename.lower() in ['flow', 'flow.json']:
        return 'Flow'
    else:
        return 'Other'

def build_table_relationships(table_mappings, node_relationships):
    """Build relationships between tables based on node connections"""
    for node_id, node_info in node_relationships.items():
        if node_info['tables']:
            # Find parent and child relationships
            for input_node_id in node_info['inputs']:
                if input_node_id in node_relationships:
                    parent_tables = node_relationships[input_node_id]['tables']
                    current_tables = node_info['tables']
                    
                    # Create relationship mappings
                    for parent_table in parent_tables:
                        for current_table in current_tables:
                            if parent_table in table_mappings:
                                if 'relationships' not in table_mappings[parent_table]:
                                    table_mappings[parent_table]['relationships'] = []
                                
                                table_mappings[parent_table]['relationships'].append({
                                    'target_table': current_table,
                                    'relationship_type': 'flows_to',
                                    'through_node': node_info['name'],
                                    'node_type': node_info['type']
                                })

def enhance_table_mappings_with_metadata(table_mappings, metadata):
    """Enhance table mappings using extracted metadata"""
    # Enhance with connection metadata
    for conn_metadata in metadata.get('connections', []):
        server = conn_metadata.get('server', '')
        database = conn_metadata.get('database', '')
        
        # Find matching tables and enhance them
        for table_key, table_info in table_mappings.items():
            if (table_info.get('server') == server or 
                table_info.get('database') == database):
                
                table_info['enhanced_metadata'] = conn_metadata

def extract_tables_from_json_recursive_enhanced(data, deep_analysis, path=""):
    """Enhanced recursive search with pattern recognition and context tracking"""
    tables = {}
    
    if isinstance(data, dict):
        # Enhanced table key detection
        table_keys = [
            'table', 'tableName', 'relation', 'relationName', 'dataSource',
            'entity', 'entityName', 'objectName', 'resource', 'source'
        ]
        
        for key, value in data.items():
            if key in table_keys and isinstance(value, str) and value.strip() and value != 'Unknown':
                table = clean_table_name(value)
                if table:
                    # Enhanced context extraction
                    context = extract_enhanced_context(data, key, deep_analysis)
                    
                    tables[table] = {
                        'table': table,
                        'schema': context.get('schema', ''),
                        'database': context.get('database', ''),
                        'full_name': context.get('full_name', table),
                        'json_path': path,
                        'context': context,
                        'extraction_method': 'enhanced_recursive_search'
                    }
            
            # Recurse into nested structures
            elif isinstance(value, (dict, list)):
                nested_tables = extract_tables_from_json_recursive_enhanced(
                    value, deep_analysis, f"{path}.{key}" if path else key
                )
                tables.update(nested_tables)
    
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                nested_tables = extract_tables_from_json_recursive_enhanced(
                    item, deep_analysis, f"{path}[{i}]"
                )
                tables.update(nested_tables)
    
    return tables

def extract_enhanced_context(data, table_key, deep_analysis):
    """Extract enhanced context information from surrounding data"""
    context = {}
    
    # Look for schema and database in the same dict
    context_keys = {
        'schema': ['schema', 'owner', 'schemaName'],
        'database': ['database', 'dbname', 'databaseName', 'catalog'],
        'server': ['server', 'hostname', 'host', 'serverName']
    }
    
    for context_type, key_list in context_keys.items():
        for key in key_list:
            if key in data and data[key]:
                context[context_type] = data[key].strip()
                break
    
    # Build full name
    table = data[table_key]
    name_components = [
        context.get('server', ''),
        context.get('database', ''),
        context.get('schema', ''),
        table
    ]
    context['full_name'] = '.'.join(comp for comp in name_components if comp)
    
    # Deep analysis: extract additional context
    if deep_analysis:
        context['all_keys'] = list(data.keys())
        context['data_types'] = {k: type(v).__name__ for k, v in data.items()}
        context['nested_objects'] = [k for k, v in data.items() if isinstance(v, dict)]
    
    return context

def extract_tables_from_enhanced_text_patterns(content, deep_analysis):
    """Enhanced pattern-based extraction with context awareness"""
    tables = {}
    
    # Comprehensive pattern collection
    enhanced_patterns = [
        # Basic table patterns
        r'"table"\s*:\s*"([^"]+)"',
        r'"tableName"\s*:\s*"([^"]+)"',
        r'"relation"\s*:\s*"([^"]+)"',
        
        # Qualified name patterns
        r'"name"\s*:\s*"([^"\.]+\.[^"\.]+\.[^"]+)"',
        r'"fullName"\s*:\s*"([^"]+)"',
        
        # SQL patterns
        r'\bFROM\s+([^\s;,()]+)',
        r'\bJOIN\s+([^\s;,()]+)',
        r'\bINTO\s+([^\s;,()]+)',
        r'\bUPDATE\s+([^\s;,()]+)',
        
        # Connection string patterns
        r'table\s*=\s*([^;\s&]+)',
        r'relation\s*=\s*([^;\s&]+)',
        
        # XML-like patterns in text
        r'<table[^>]*>([^<]+)</table>',
        r'table\s*=\s*["\']([^"\']+)["\']',
    ]
    
    for i, pattern in enumerate(enhanced_patterns):
        matches = re.findall(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if match and match != 'Unknown':
                table = clean_table_name(match)
                if table:
                    # Enhanced table information
                    table_info = {
                        'table': table,
                        'schema': '',
                        'database': '',
                        'full_name': table,
                        'pattern_match': pattern,
                        'extraction_method': f'enhanced_pattern_{i+1}'
                    }
                    
                    # Parse qualified names
                    if '.' in table:
                        parts = table.split('.')
                        if len(parts) >= 2:
                            table_info['table'] = parts[-1]
                            table_info['schema'] = parts[-2] if len(parts) > 1 else ''
                            table_info['database'] = parts[-3] if len(parts) > 2 else ''
                            table_info['full_name'] = table
                    
                    # Deep analysis: extract surrounding context
                    if deep_analysis:
                        table_info['surrounding_context'] = extract_pattern_context(content, match)
                    
                    tables[table_info['table']] = table_info
    
    return tables

def extract_pattern_context(content, match):
    """Extract surrounding context for pattern matches"""
    try:
        match_index = content.find(match)
        if match_index != -1:
            # Extract lines around the match
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if match in line:
                    start_line = max(0, i - 2)
                    end_line = min(len(lines), i + 3)
                    return '\n'.join(lines[start_line:end_line])
    except:
        pass
    return ''

def export_enhanced_table_mappings_to_csv(result, output_file):
    """Export enhanced table mappings with comprehensive details"""
    try:
        table_mappings = result['table_mappings']
        
        # Determine fieldnames based on available data
        base_fieldnames = [
            'Table Name', 'Schema', 'Database', 'Server', 'Port', 'Full Name', 
            'Database Type', 'Node Name', 'Node ID', 'Connection Class',
            'Extraction Method'
        ]
        
        # Add deep analysis fields if available
        has_deep_analysis = any('enhanced_metadata' in info or 'relationships' in info 
                              for info in table_mappings.values())
        
        if has_deep_analysis:
            base_fieldnames.extend([
                'Relationships', 'Column Count', 'Has Keys', 'Connection String',
                'Additional Metadata', 'Context Info'
            ])
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=base_fieldnames)
            writer.writeheader()
            
            # Sort by database type, server, schema, table
            sorted_tables = sorted(
                table_mappings.items(),
                key=lambda x: (
                    x[1].get('database_type', 'ZZZ'),
                    x[1].get('server', 'ZZZ'),
                    x[1].get('schema', 'ZZZ'),
                    x[1].get('table', 'ZZZ')
                )
            )
            
            for table_key, table_info in sorted_tables:
                row_data = {
                    'Table Name': table_info.get('table', ''),
                    'Schema': table_info.get('schema', ''),
                    'Database': table_info.get('database', ''),
                    'Server': table_info.get('server', ''),
                    'Port': table_info.get('port', ''),
                    'Full Name': table_info.get('full_name', ''),
                    'Database Type': table_info.get('database_type', ''),
                    'Node Name': table_info.get('node_name', ''),
                    'Node ID': table_info.get('node_id', ''),
                    'Connection Class': table_info.get('connection_class', ''),
                    'Extraction Method': table_info.get('extraction_method', '')
                }
                
                # Add deep analysis data if available
                if has_deep_analysis:
                    # Relationships
                    relationships = table_info.get('relationships', [])
                    rel_summary = "; ".join([
                        f"{rel['target_table']} ({rel['relationship_type']})"
                        for rel in relationships[:3]  # Limit to first 3
                    ])
                    
                    # Additional metadata compilation
                    additional_metadata = []
                    if 'enhanced_metadata' in table_info:
                        meta = table_info['enhanced_metadata']
                        additional_metadata.append(f"Type: {meta.get('type', '')}")
                        additional_metadata.append(f"Class: {meta.get('class', '')}")
                    
                    if 'additional_properties' in table_info:
                        props = table_info['additional_properties']
                        additional_metadata.append(f"Properties: {len(props)}")
                    
                    # Context information
                    context_info = []
                    if 'context' in table_info:
                        ctx = table_info['context']
                        if 'all_keys' in ctx:
                            context_info.append(f"Keys: {len(ctx['all_keys'])}")
                        if 'nested_objects' in ctx:
                            context_info.append(f"Nested: {len(ctx['nested_objects'])}")
                    
                    if 'surrounding_context' in table_info:
                        context_info.append("Has surrounding context")
                    
                    row_data.update({
                        'Relationships': rel_summary,
                        'Column Count': table_info.get('column_count', ''),
                        'Has Keys': 'Yes' if table_info.get('has_keys') else 'No',
                        'Connection String': table_info.get('connection_string', ''),
                        'Additional Metadata': " | ".join(additional_metadata),
                        'Context Info': " | ".join(context_info)
                    })
                
                writer.writerow(row_data)
        
        print(f"✅ Enhanced table mappings exported to: {output_file}")
        
        # Create additional analysis files
        create_enhanced_analysis_files(result, output_file)
        
    except Exception as e:
        print(f"❌ Error writing enhanced CSV files: {e}")
        import traceback
        traceback.print_exc()

def create_enhanced_analysis_files(result, base_output_file):
    """Create additional enhanced analysis files"""
    base_name = base_output_file.replace('.csv', '')
    table_mappings = result['table_mappings']
    node_relationships = result['node_relationships']
    extraction_stats = result['extraction_stats']
    
    try:
        # 1. Database Type Analysis
        db_analysis_file = f"{base_name}_database_analysis.csv"
        create_database_type_analysis_enhanced(table_mappings, db_analysis_file)
        
        # 2. Extraction Method Analysis
        method_analysis_file = f"{base_name}_extraction_analysis.csv"
        create_extraction_method_analysis(table_mappings, extraction_stats, method_analysis_file)
        
        # 3. Relationship Analysis (if available)
        if node_relationships:
            relationship_file = f"{base_name}_relationships.csv"
            create_relationship_analysis(table_mappings, node_relationships, relationship_file)
        
        # 4. Schema/Database Analysis
        schema_analysis_file = f"{base_name}_schema_analysis.csv"
        create_schema_database_analysis(table_mappings, schema_analysis_file)
        
    except Exception as e:
        print(f"❌ Error creating enhanced analysis files: {e}")

def create_database_type_analysis_enhanced(table_mappings, output_file):
    """Create enhanced database type analysis"""
    try:
        db_summary = defaultdict(lambda: {
            'count': 0,
            'unique_tables': set(),
            'unique_schemas': set(),
            'unique_databases': set(),
            'unique_servers': set(),
            'extraction_methods': defaultdict(int)
        })
        
        for table_info in table_mappings.values():
            db_type = table_info.get('database_type', 'Unknown')
            method = table_info.get('extraction_method', 'Unknown')
            
            summary = db_summary[db_type]
            summary['count'] += 1
            summary['unique_tables'].add(table_info.get('table', ''))
            summary['extraction_methods'][method] += 1
            
            if table_info.get('schema'):
                summary['unique_schemas'].add(table_info['schema'])
            if table_info.get('database'):
                summary['unique_databases'].add(table_info['database'])
            if table_info.get('server'):
                summary['unique_servers'].add(table_info['server'])
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Database Type', 'Table Count', 'Unique Schemas', 'Unique Databases',
                'Unique Servers', 'Primary Extraction Method', 'Method Distribution'
            ]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            
            for db_type, summary in sorted(db_summary.items(), key=lambda x: x[1]['count'], reverse=True):
                # Find primary extraction method
                primary_method = max(summary['extraction_methods'].items(), 
                                   key=lambda x: x[1])[0] if summary['extraction_methods'] else 'Unknown'
                
                # Create method distribution string
                method_dist = ", ".join([
                    f"{method}: {count}" for method, count in 
                    sorted(summary['extraction_methods'].items(), key=lambda x: x[1], reverse=True)
                ])
                
                writer.writerow({
                    'Database Type': db_type,
                    'Table Count': summary['count'],
                    'Unique Schemas': len(summary['unique_schemas']),
                    'Unique Databases': len(summary['unique_databases']),
                    'Unique Servers': len(summary['unique_servers']),
                    'Primary Extraction Method': primary_method,
                    'Method Distribution': method_dist
                })
        
        print(f"✅ Database type analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating database type analysis: {e}")

def create_extraction_method_analysis(table_mappings, extraction_stats, output_file):
    """Create extraction method effectiveness analysis"""
    try:
        method_summary = defaultdict(lambda: {
            'count': 0,
            'database_types': defaultdict(int),
            'success_contexts': []
        })
        
        for table_info in table_mappings.values():
            method = table_info.get('extraction_method', 'Unknown')
            db_type = table_info.get('database_type', 'Unknown')
            
            method_summary[method]['count'] += 1
            method_summary[method]['database_types'][db_type] += 1
            
            # Track successful extraction contexts
            if 'node_name' in table_info:
                method_summary[method]['success_contexts'].append(table_info['node_name'])
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Method effectiveness summary
            writer.writerow(['=== EXTRACTION METHOD EFFECTIVENESS ==='])
            writer.writerow(['Method', 'Count', 'Percentage', 'Primary DB Type', 'Success Rate'])
            
            total_extractions = sum(method['count'] for method in method_summary.values())
            
            for method, summary in sorted(method_summary.items(), key=lambda x: x[1]['count'], reverse=True):
                percentage = (summary['count'] / total_extractions * 100) if total_extractions > 0 else 0
                primary_db = max(summary['database_types'].items(), 
                               key=lambda x: x[1])[0] if summary['database_types'] else 'Unknown'
                
                writer.writerow([
                    method, summary['count'], f"{percentage:.1f}%", 
                    primary_db, "High"  # Simplified success rate
                ])
            
            writer.writerow([])
            
            # Overall statistics
            writer.writerow(['=== OVERALL EXTRACTION STATISTICS ==='])
            writer.writerow(['Statistic', 'Value'])
            
            for stat_name, count in extraction_stats.items():
                writer.writerow([stat_name.replace('_', ' ').title(), count])
            
            writer.writerow(['Total Unique Tables', len(table_mappings)])
            writer.writerow(['Total Extraction Methods', len(method_summary)])
        
        print(f"✅ Extraction method analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating extraction method analysis: {e}")

def create_relationship_analysis(table_mappings, node_relationships, output_file):
    """Create table relationship analysis"""
    try:
        relationships = []
        
        for table_key, table_info in table_mappings.items():
            if 'relationships' in table_info:
                for rel in table_info['relationships']:
                    relationships.append({
                        'Source Table': table_key,
                        'Target Table': rel['target_table'],
                        'Relationship Type': rel['relationship_type'],
                        'Through Node': rel['through_node'],
                        'Node Type': rel['node_type']
                    })
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            if relationships:
                fieldnames = ['Source Table', 'Target Table', 'Relationship Type', 'Through Node', 'Node Type']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(relationships)
                
                print(f"✅ Relationship analysis written to: {output_file}")
                print(f"    Found {len(relationships)} table relationships")
            else:
                writer = csv.writer(csvfile)
                writer.writerow(['No table relationships found in the analysis'])
                print(f"✅ Relationship analysis written to: {output_file} (no relationships found)")
        
    except Exception as e:
        print(f"❌ Error creating relationship analysis: {e}")

def create_schema_database_analysis(table_mappings, output_file):
    """Create schema and database distribution analysis"""
    try:
        schema_summary = defaultdict(lambda: {
            'table_count': 0,
            'database_types': defaultdict(int),
            'servers': set(),
            'tables': set()
        })
        
        database_summary = defaultdict(lambda: {
            'table_count': 0,
            'schemas': set(),
            'database_types': defaultdict(int),
            'servers': set()
        })
        
        for table_info in table_mappings.values():
            schema = table_info.get('schema', 'No Schema')
            database = table_info.get('database', 'No Database')
            db_type = table_info.get('database_type', 'Unknown')
            server = table_info.get('server', '')
            table = table_info.get('table', '')
            
            # Schema analysis
            schema_summary[schema]['table_count'] += 1
            schema_summary[schema]['database_types'][db_type] += 1
            schema_summary[schema]['tables'].add(table)
            if server:
                schema_summary[schema]['servers'].add(server)
            
            # Database analysis
            database_summary[database]['table_count'] += 1
            database_summary[database]['schemas'].add(schema)
            database_summary[database]['database_types'][db_type] += 1
            if server:
                database_summary[database]['servers'].add(server)
        
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.writer(csvfile)
            
            # Schema analysis
            writer.writerow(['=== SCHEMA ANALYSIS ==='])
            writer.writerow(['Schema', 'Table Count', 'Unique Tables', 'Servers', 'Primary DB Type'])
            
            for schema, summary in sorted(schema_summary.items(), key=lambda x: x[1]['table_count'], reverse=True):
                primary_db = max(summary['database_types'].items(), 
                               key=lambda x: x[1])[0] if summary['database_types'] else 'Unknown'
                
                writer.writerow([
                    schema, 
                    summary['table_count'],
                    len(summary['tables']),
                    len(summary['servers']),
                    primary_db
                ])
            
            writer.writerow([])
            
            # Database analysis
            writer.writerow(['=== DATABASE ANALYSIS ==='])
            writer.writerow(['Database', 'Table Count', 'Unique Schemas', 'Servers', 'Primary DB Type'])
            
            for database, summary in sorted(database_summary.items(), key=lambda x: x[1]['table_count'], reverse=True):
                primary_db = max(summary['database_types'].items(), 
                               key=lambda x: x[1])[0] if summary['database_types'] else 'Unknown'
                
                writer.writerow([
                    database,
                    summary['table_count'],
                    len(summary['schemas']),
                    len(summary['servers']),
                    primary_db
                ])
        
        print(f"✅ Schema/Database analysis written to: {output_file}")
        
    except Exception as e:
        print(f"❌ Error creating schema/database analysis: {e}")

def main():
    """Main function with comprehensive enhanced interactive interface"""
    try:
        file_path, output_csv, deep_analysis = get_user_inputs()
        
        print(f"🚀 Starting comprehensive enhanced table mapping extraction...")
        result = extract_comprehensive_table_mappings(file_path, deep_analysis)
        
        table_mappings = result['table_mappings']
        node_relationships = result['node_relationships']
        extraction_stats = result['extraction_stats']
        
        if table_mappings:
            print(f"\n📊 ENHANCED EXTRACTION RESULTS")
            print(f"{'='*80}")
            print(f"✅ Found {len(table_mappings)} table mappings")
            
            # Enhanced results display
            display_enhanced_results(table_mappings, node_relationships, extraction_stats, deep_analysis)
            
            # Export to CSV if requested
            if output_csv:
                export_enhanced_table_mappings_to_csv(result, output_csv)
            
        else:
            print("\n❌ No table mappings found in the file")
            print("   This could mean:")
            print("   • The flow file doesn't contain database connections")
            print("   • Tables are referenced in a format not recognized")
            print("   • The file structure is different than expected")
            print("   • All table references are in file sources (not databases)")
        
        if deep_analysis:
            print(f"\n🔍 Deep analysis provided:")
            print(f"  • Node relationship mapping: {len(node_relationships)} nodes")
            print(f"  • Enhanced metadata extraction")
            print(f"  • Comprehensive pattern recognition")
            print(f"  • Context-aware table resolution")
        
        print(f"\n🎉 Enhanced table mapping extraction complete!")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Extraction interrupted by user")
    except Exception as e:
        print(f"\n❌ Error during enhanced extraction: {e}")
        import traceback
        traceback.print_exc()

def display_enhanced_results(table_mappings, node_relationships, extraction_stats, deep_analysis):
    """Display enhanced results with comprehensive breakdown"""
    
    # Group by database type
    by_db_type = defaultdict(list)
    for table_key, table_info in table_mappings.items():
        db_type = table_info.get('database_type', 'Unknown')
        by_db_type[db_type].append(table_info)
    
    # Display by database type
    for db_type, tables in sorted(by_db_type.items(), key=lambda x: len(x[1]), reverse=True):
        print(f"\n🗄️ {db_type} ({len(tables)} tables):")
        
        # Show sample tables with enhanced info
        for table_info in sorted(tables, key=lambda x: x['full_name'])[:3]:
            full_name = table_info['full_name']
            method = table_info['extraction_method']
            node_name = table_info.get('node_name', 'N/A')
            
            print(f"  📋 {full_name}")
            print(f"      Method: {method}")
            if node_name != 'N/A':
                print(f"      Node: {node_name}")
            
            # Show relationships if available
            if deep_analysis and 'relationships' in table_info:
                rel_count = len(table_info['relationships'])
                if rel_count > 0:
                    print(f"      Relationships: {rel_count}")
        
        if len(tables) > 3:
            print(f"      ... and {len(tables) - 3} more")
    
    # Enhanced extraction method breakdown
    method_counts = defaultdict(int)
    for table_info in table_mappings.values():
        method_counts[table_info.get('extraction_method', 'Unknown')] += 1
    
    print(f"\n🔍 Enhanced extraction method breakdown:")
    for method, count in sorted(method_counts.items(), key=lambda x: x[1], reverse=True):
        percentage = (count / len(table_mappings) * 100) if table_mappings else 0
        print(f"  {method}: {count} tables ({percentage:.1f}%)")
    
    # Server/Schema analysis
    unique_servers = set(info.get('server', '') for info in table_mappings.values() if info.get('server'))
    unique_schemas = set(info.get('schema', '') for info in table_mappings.values() if info.get('schema'))
    unique_databases = set(info.get('database', '') for info in table_mappings.values() if info.get('database'))
    
    print(f"\n📋 Enhanced distribution analysis:")
    print(f"  Unique servers: {len(unique_servers)}")
    if unique_servers and len(unique_servers) <= 5:
        print(f"    Servers: {', '.join(sorted(unique_servers))}")
    
    print(f"  Unique databases: {len(unique_databases)}")
    if unique_databases and len(unique_databases) <= 5:
        print(f"    Databases: {', '.join(sorted(unique_databases))}")
    
    print(f"  Unique schemas: {len(unique_schemas)}")
    if unique_schemas and len(unique_schemas) <= 5:
        print(f"    Schemas: {', '.join(sorted(unique_schemas))}")
    
    # Deep analysis statistics
    if deep_analysis:
        print(f"\n🔍 Deep analysis statistics:")
        
        # Relationship statistics
        total_relationships = sum(
            len(info.get('relationships', [])) for info in table_mappings.values()
        )
        if total_relationships > 0:
            print(f"  Table relationships found: {total_relationships}")
        
        # Metadata statistics
        enhanced_metadata_count = sum(
            1 for info in table_mappings.values() if 'enhanced_metadata' in info
        )
        if enhanced_metadata_count > 0:
            print(f"  Tables with enhanced metadata: {enhanced_metadata_count}")
        
        # Context information
        context_info_count = sum(
            1 for info in table_mappings.values() if 'context' in info
        )
        if context_info_count > 0:
            print(f"  Tables with context information: {context_info_count}")

if __name__ == "__main__":
    main()