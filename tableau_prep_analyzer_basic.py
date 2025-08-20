import os
import csv
import zipfile
import json
import xml.etree.ElementTree as ET
from io import TextIOWrapper
from collections import defaultdict
from pathlib import Path
import re
import shutil
import tempfile
from datetime import datetime

def get_user_inputs():
    """Interactive prompts for user inputs"""
    print("=== Tableau Prep Flow Analyzer - Basic Version ===")
    print("Analyze Tableau Prep flows for field usage and transformations")
    print()
    
    # Get input directory
    while True:
        input_dir = input("Enter the directory path containing .tfl/.tflx files: ").strip()
        if os.path.exists(input_dir):
            break
        print(f"Error: Directory '{input_dir}' does not exist. Please try again.")
    
    # Get output directory
    output_dir = input("Enter output directory (press Enter for auto-generated): ").strip()
    if not output_dir:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = f"tableau_prep_analysis_basic_{timestamp}"
    
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
            database_filter = filter_map[choice]
            break
        print("Invalid choice. Please enter 1-5.")
    
    # Clear output option
    clear_output = input("Clear output directory if it exists? (y/n): ").strip().lower() == 'y'
    
    return input_dir, output_dir, database_filter, clear_output

def should_include_file(file_path, database_filter):
    """Check if file should be included based on database filter"""
    if database_filter is None:
        return True
    
    path_lower = str(file_path).lower()
    db_indicators = {
        'Oracle': ['oracle', 'ora_', '_ora', 'orcl'],
        'SQL Server': ['sqlserver', 'mssql', 'sql_server', '_ss', 'ss_'],
        'PostgreSQL': ['postgres', 'pg_', '_pg', 'postgresql'],
        'MySQL': ['mysql', 'my_', '_my']
    }
    
    if database_filter in db_indicators:
        return any(indicator in path_lower for indicator in db_indicators[database_filter])
    
    return True

def get_connection_info(flow_json, connection_id):
    """Extract connection information from flow JSON"""
    conn_info = {}
    
    if 'connections' in flow_json:
        connections = flow_json['connections']
        if isinstance(connections, dict) and connection_id in connections:
            conn_info = connections[connection_id]
    
    return conn_info

def extract_data_source_info(node, node_name, flow_json):
    """Extract data source information with comprehensive fallback methods"""
    connection_id = node.get('connectionId')
    connection_attrs = node.get('connectionAttributes', {})
    node_type = node.get('nodeType', '').lower()
    
    print(f"    Extracting data source for: {node_name}")
    
    # Handle Tableau Server sources
    if 'proxy' in node_type or 'sqlproxy' in connection_attrs.get('class', '').lower():
        datasource_name = (
            connection_attrs.get('datasourceName') or 
            connection_attrs.get('name') or 
            'Unknown'
        )
        result = f"Tableau Server: {datasource_name}"
        print(f"    Detected Tableau Server source: {result}")
        return result
    
    # Handle file-based sources
    elif any(file_type in node_type for file_type in ['file', 'excel', 'csv', 'text', 'input']):
        file_path = (
            connection_attrs.get('filename') or 
            connection_attrs.get('path') or 
            connection_attrs.get('file') or 
            connection_attrs.get('filepath') or
            node.get('file') or
            'Unknown'
        )
        
        # Detect file type
        file_type = "File"
        if file_path != 'Unknown':
            if any(ext in file_path.lower() for ext in ['.csv', '.txt']):
                file_type = "CSV/Text File"
            elif any(ext in file_path.lower() for ext in ['.xls', '.xlsx']):
                file_type = "Excel File"
            elif any(ext in file_path.lower() for ext in ['.json']):
                file_type = "JSON File"
        
        result = f"{file_type}: {file_path}"
        print(f"    Detected file source: {result}")
        return result
    
    # Handle SQL databases
    elif 'sql' in node_type or connection_id:
        conn_info = get_connection_info(flow_json, connection_id)
        
        # Extract server/database info
        server = (
            connection_attrs.get('server') or 
            conn_info.get('server') or 
            connection_attrs.get('hostname') or 
            'localhost'
        )
        
        database = (
            connection_attrs.get('database') or 
            conn_info.get('database') or 
            connection_attrs.get('dbname') or 
            'Unknown'
        )
        
        schema = (
            connection_attrs.get('schema') or 
            conn_info.get('schema') or 
            'Unknown'
        )
        
        table = (
            connection_attrs.get('table') or 
            node.get('relation', {}).get('table') if isinstance(node.get('relation'), dict) else None or
            'Unknown'
        )
        
        # Clean table name
        if table:
            table = table.strip('[]"`')
        
        # Determine database type
        db_class = conn_info.get('class', '').lower()
        
        if 'oracle' in db_class or 'oracle' in server.lower():
            db_type = 'Oracle'
        elif 'sqlserver' in db_class or 'sql' in db_class:
            db_type = 'SQL Server'
        elif 'postgres' in db_class:
            db_type = 'PostgreSQL'
        elif 'mysql' in db_class:
            db_type = 'MySQL'
        else:
            db_type = 'Database'
        
        data_source = f"{db_type}: {server}.{schema}.{table}"
        print(f"    Detected database source: {data_source}")
        return data_source
    
    # Fallback: try to extract from relation
    elif 'relation' in node:
        relation = node['relation']
        if isinstance(relation, dict):
            table = relation.get('table', 'Unknown')
            schema = relation.get('schema', 'Unknown')
            result = f"Database: {schema}.{table}"
            print(f"    Fallback extraction: {result}")
            return result
    
    print(f"    Could not determine data source for: {node_name}")
    return f"Unknown: {node_name}"

def find_field_references_in_text(text, field_list):
    """Find field references in calculation text"""
    if not text or not field_list:
        return set()
    
    referenced_fields = set()
    text_upper = text.upper()
    
    for field in field_list:
        field_upper = field.upper()
        
        # Exact matches with word boundaries
        pattern = r'\b' + re.escape(field_upper) + r'\b'
        if re.search(pattern, text_upper):
            referenced_fields.add(field)
            continue
        
        # Bracketed references [Field Name]
        bracketed_pattern = r'$$' + re.escape(field) + r'$$'
        if re.search(bracketed_pattern, text, re.IGNORECASE):
            referenced_fields.add(field)
    
    return referenced_fields

def analyze_flow_file_basic(flow_file, database_filter):
    """Basic comprehensive analysis of a flow file"""
    print(f"\n📁 Processing: {flow_file.name}")
    
    if not should_include_file(str(flow_file), database_filter):
        print(f"⏭️ Skipped (database filter: {database_filter})")
        return None
    
    temp_dir = tempfile.mkdtemp()
    
    try:
        # Extract and read flow content
        if flow_file.suffix.lower() == '.tfl':
            with open(flow_file, 'r', encoding='utf-8') as f:
                flow_content = f.read()
        elif flow_file.suffix.lower() == '.tflx':
            with zipfile.ZipFile(flow_file, 'r') as zf:
                zf.extractall(temp_dir)
                flow_path = Path(temp_dir) / "flow"
                if not flow_path.exists():
                    # Try alternative locations
                    for item in Path(temp_dir).rglob("*"):
                        if item.name.lower() in ['flow', 'flow.json']:
                            flow_path = item
                            break
                
                if not flow_path.exists():
                    print(f"❌ No flow file found in {flow_file.name}")
                    return None
                
                with open(flow_path, 'r', encoding='utf-8') as f:
                    flow_content = f.read()
        else:
            print(f"❌ Unsupported file type: {flow_file.suffix}")
            return None
        
        try:
            flow_json = json.loads(flow_content)
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in {flow_file.name}: {e}")
            return None
        
        # Initialize tracking
        input_fields = {}
        actual_output_fields = {}
        field_sources = {}
        transformations = {
            'calculations': {},
            'renames': {},
            'filters': [],
            'joins': [],
            'group_by_fields': set(),
            'aggregate_fields': {}
        }
        
        used_fields = set()
        all_fields = set()
        field_dependencies = defaultdict(set)
        node_outputs = {}
        
        def process_node(node):
            nonlocal input_fields, actual_output_fields, field_sources, transformations, used_fields, all_fields
            
            if not isinstance(node, dict):
                return
            
            node_type = node.get('nodeType', '').lower()
            node_name = node.get('name', 'Unnamed Node')
            node_id = node.get('id', 'unknown_id')
            
            print(f"  🔍 Processing node: {node_name} (Type: {node_type})")
            
            # Process INPUT nodes
            if any(input_type in node_type for input_type in ['input', 'load', 'extract', 'source']):
                data_source = extract_data_source_info(node, node_name, flow_json)
                
                # Process fields from relation
                if 'relation' in node and isinstance(node['relation'], dict):
                    relation = node['relation']
                    if 'columns' in relation and isinstance(relation['columns'], dict):
                        for field_name, field_info in relation['columns'].items():
                            if isinstance(field_info, dict):
                                original_name = field_info.get('name', field_name)
                                data_type = field_info.get('type', 'unknown')
                                
                                input_fields[field_name] = {
                                    "original_name": original_name,
                                    "data_type": data_type,
                                    "source_node": node_name
                                }
                                field_sources[field_name] = data_source
                                all_fields.add(field_name)
                                print(f"    📥 Input Field: {field_name} from {data_source}")
                
                # Also check direct fields array
                if 'fields' in node:
                    fields = node['fields']
                    if isinstance(fields, dict):
                        for field_name, field_info in fields.items():
                            if isinstance(field_info, dict) and field_name not in input_fields:
                                original_name = field_info.get('remoteFieldName', field_name)
                                data_type = field_info.get('type', 'unknown')
                                
                                input_fields[field_name] = {
                                    "original_name": original_name,
                                    "data_type": data_type,
                                    "source_node": node_name
                                }
                                field_sources[field_name] = data_source
                                all_fields.add(field_name)
                                print(f"    📥 Input Field: {field_name} from {data_source}")
                    elif isinstance(fields, list):
                        for field_info in fields:
                            if isinstance(field_info, dict):
                                field_name = field_info.get('name')
                                if field_name and field_name not in input_fields:
                                    original_name = field_info.get('remoteFieldName', field_name)
                                    data_type = field_info.get('type', 'unknown')
                                    
                                    input_fields[field_name] = {
                                        "original_name": original_name,
                                        "data_type": data_type,
                                        "source_node": node_name
                                    }
                                    field_sources[field_name] = data_source
                                    all_fields.add(field_name)
                                    print(f"    📥 Input Field: {field_name} from {data_source}")
            
            # Process CALCULATION nodes
            elif 'calculation' in node_type or 'addcolumn' in node_type:
                column_name = node.get('columnName') or node.get('name')
                expression = node.get('expression') or node.get('formula')
                
                if column_name and expression:
                    transformations['calculations'][column_name] = expression
                    all_fields.add(column_name)
                    used_fields.add(column_name)
                    
                    # Find referenced fields
                    referenced_fields = find_field_references_in_text(expression, all_fields)
                    for ref_field in referenced_fields:
                        used_fields.add(ref_field)
                        field_dependencies[column_name].add(ref_field)
                    
                    print(f"    🧮 Calculation: {column_name} = {expression[:30]}...")
            
            # Process RENAME nodes
            elif 'rename' in node_type:
                old_name = node.get('columnName')
                new_name = node.get('rename')
                
                if old_name and new_name:
                    transformations['renames'][new_name] = old_name
                    all_fields.add(old_name)
                    all_fields.add(new_name)
                    used_fields.add(old_name)
                    used_fields.add(new_name)
                    field_dependencies[new_name].add(old_name)
                    print(f"    🔄 Rename: {old_name} → {new_name}")
            
            # Process JOIN nodes
            elif 'join' in node_type:
                join_clauses = node.get('joinClauses', [])
                
                for clause in join_clauses:
                    if isinstance(clause, dict):
                        left_field = clause.get('left')
                        right_field = clause.get('right')
                        
                        if left_field and right_field:
                            transformations['joins'].append({
                                'left': left_field,
                                'right': right_field,
                                'node_name': node_name
                            })
                            
                            used_fields.add(left_field)
                            used_fields.add(right_field)
                            all_fields.add(left_field)
                            all_fields.add(right_field)
                            print(f"    🔗 Join: {left_field} = {right_field}")
            
            # Process AGGREGATE nodes
            elif 'aggregate' in node_type:
                group_by = node.get('groupBy', [])
                aggregates = node.get('aggregates', [])
                
                # Process group by fields
                for field in group_by:
                    if field:
                        transformations['group_by_fields'].add(field)
                        used_fields.add(field)
                        all_fields.add(field)
                        print(f"    📊 Group By: {field}")
                
                # Process aggregate fields
                for agg in aggregates:
                    if isinstance(agg, dict):
                        field_name = agg.get('field')
                        agg_type = agg.get('type', 'SUM')
                        
                        if field_name:
                            transformations['aggregate_fields'][field_name] = agg_type
                            used_fields.add(field_name)
                            all_fields.add(field_name)
                            print(f"    📈 Aggregate: {agg_type}({field_name})")
            
            # Process FILTER nodes
            elif 'filter' in node_type:
                filter_expression = node.get('filter') or node.get('expression')
                
                if filter_expression:
                    transformations['filters'].append({
                        'expression': filter_expression,
                        'node_name': node_name
                    })
                    
                    # Find fields used in filter
                    referenced_fields = find_field_references_in_text(filter_expression, all_fields)
                    for ref_field in referenced_fields:
                        used_fields.add(ref_field)
                    
                    print(f"    🔍 Filter: {filter_expression[:30]}...")
            
            # Process OUTPUT fields from any node
            if 'fields' in node:
                fields = node['fields']
                node_output_fields = {}
                
                if isinstance(fields, dict):
                    for field_name, field_info in fields.items():
                        if isinstance(field_info, dict):
                            data_type = field_info.get('type', 'unknown')
                            all_fields.add(field_name)
                            
                            # Check for calculated fields in output
                            calc = field_info.get('calc')
                            if calc:
                                transformations['calculations'][field_name] = calc
                                referenced_fields = find_field_references_in_text(calc, all_fields)
                                for ref_field in referenced_fields:
                                    used_fields.add(ref_field)
                                    field_dependencies[field_name].add(ref_field)
                                print(f"    🧮 Output calculation: {field_name}")
                            
                            node_output_fields[field_name] = data_type
                
                node_outputs[node_id] = node_output_fields
                
                # If this is likely a final output node, mark fields as outputs
                if (node_type in ['output', 'write', 'export'] or 
                    not any(other_node.get('inputs', {}).get(node_id) for other_node in flow_json.get('nodes', {}).values())):
                    actual_output_fields.update(node_output_fields)
                    for field_name in node_output_fields:
                        used_fields.add(field_name)
                        print(f"    📤 Output field: {field_name}")
            
            # Process nested containers
            if 'loomContainer' in node:
                loom_container = node['loomContainer']
                if isinstance(loom_container, dict) and 'nodes' in loom_container:
                    print(f"    📦 Processing nested container in {node_name}")
                    for sub_node in loom_container['nodes'].values():
                        process_node(sub_node)
        
        # Process all nodes
        print(f"🔍 Processing all nodes in flow...")
        if 'nodes' in flow_json and isinstance(flow_json['nodes'], dict):
            for node in flow_json['nodes'].values():
                process_node(node)
        
        # Determine final output fields if not identified
        if not actual_output_fields:
            print("🎯 Determining final output fields...")
            all_node_ids = set(flow_json.get('nodes', {}).keys())
            referenced_nodes = set()
            
            for node in flow_json.get('nodes', {}).values():
                inputs = node.get('inputs', {})
                referenced_nodes.update(inputs.keys())
            
            output_node_ids = all_node_ids - referenced_nodes
            
            for node_id in output_node_ids:
                if node_id in node_outputs:
                    actual_output_fields.update(node_outputs[node_id])
                    for field_name in node_outputs[node_id]:
                        used_fields.add(field_name)
                        print(f"    📤 Final output field: {field_name}")
        
        # Determine usage reasons
        usage_reasons = {}
        
        # Mark output fields as used
        for field in actual_output_fields:
            used_fields.add(field)
            usage_reasons[field] = "Appears in final output"
        
        # Mark calculated field dependencies as used
        for calc_field, formula in transformations['calculations'].items():
            used_fields.add(calc_field)
            usage_reasons[calc_field] = f"Calculated field"
            
            referenced_fields = find_field_references_in_text(formula, all_fields)
            for ref_field in referenced_fields:
                used_fields.add(ref_field)
                if ref_field not in usage_reasons:
                    usage_reasons[ref_field] = f"Used in calculation: {calc_field}"
                else:
                    usage_reasons[ref_field] += f" | Used in calculation: {calc_field}"
        
        # Mark renamed fields as used
        for new_name, old_name in transformations['renames'].items():
            used_fields.add(old_name)
            used_fields.add(new_name)
            usage_reasons[old_name] = f"Renamed to: {new_name}"
            if new_name not in usage_reasons:
                usage_reasons[new_name] = f"Renamed from: {old_name}"
        
        # Mark group by fields as used
        for field in transformations['group_by_fields']:
            used_fields.add(field)
            if field not in usage_reasons:
                usage_reasons[field] = "Used in GROUP BY"
            else:
                usage_reasons[field] += " | Used in GROUP BY"
        
        # Mark aggregate fields as used
        for field, agg_type in transformations['aggregate_fields'].items():
            used_fields.add(field)
            if field not in usage_reasons:
                usage_reasons[field] = f"Used in {agg_type} aggregation"
            else:
                usage_reasons[field] += f" | Used in {agg_type} aggregation"
        
        # Mark join fields as used
        for join in transformations['joins']:
            for field in [join['left'], join['right']]:
                used_fields.add(field)
                if field not in usage_reasons:
                    usage_reasons[field] = "Used in join condition"
                else:
                    usage_reasons[field] += " | Used in join condition"
        
        # Mark filter fields as used
        for filter_info in transformations['filters']:
            referenced_fields = find_field_references_in_text(filter_info['expression'], all_fields)
            for ref_field in referenced_fields:
                used_fields.add(ref_field)
                if ref_field not in usage_reasons:
                    usage_reasons[ref_field] = "Used in filter condition"
                else:
                    usage_reasons[ref_field] += " | Used in filter condition"
        
        # Mark unused fields
        for field in input_fields:
            if field not in used_fields:
                usage_reasons[field] = "❌ Not used in any transformations or output"
        
        result = {
            'file_path': str(flow_file),
            'input_fields': input_fields,
            'output_fields': actual_output_fields,
            'field_sources': field_sources,
            'all_fields': all_fields,
            'transformations': transformations,
            'used_fields': used_fields,
            'usage_reasons': usage_reasons
        }
        
        print(f"✅ Analysis complete:")
        print(f"   📥 Input fields: {len(input_fields)}")
        print(f"   📤 Output fields: {len(actual_output_fields)}")
        print(f"   🔧 Transformations: {sum(len(v) if isinstance(v, (list, set, dict)) else 1 for v in transformations.values())}")
        print(f"   ✅ Used fields: {len(used_fields)}")
        print(f"   📊 All fields tracked: {len(all_fields)}")
        
        return result
    
    except Exception as e:
        print(f"❌ Error processing {flow_file.name}: {str(e)}")
        import traceback
        traceback.print_exc()
        return None
    
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

def extract_field_usage_with_csv(flow_file, output_folder, database_filter):
    """Extract and write basic CSV outputs"""
    result = analyze_flow_file_basic(flow_file, database_filter)
    
    if not result:
        return False
    
    output_folder.mkdir(parents=True, exist_ok=True)
    flow_name = Path(flow_file).stem
    
    try:
        # 1. Input Fields CSV
        input_fields_data = []
        for field_name, field_info in result['input_fields'].items():
            data_source = result['field_sources'].get(field_name, 'Unknown')
            input_fields_data.append([
                field_name,
                field_info['original_name'],
                field_info['data_type'],
                data_source,
                field_info['source_node']
            ])
        
        write_csv(output_folder / f"input_fields_{flow_name}.csv",
                 ["Field Name", "Original Name", "Data Type", "Data Source", "Source Node"],
                 input_fields_data)
        
        # 2. Output Fields CSV
        output_fields_data = []
        for field_name, data_type in result['output_fields'].items():
            output_fields_data.append([field_name, data_type])
        
        write_csv(output_folder / f"output_fields_{flow_name}.csv",
                 ["Field Name", "Data Type"],
                 output_fields_data)
        
        # 3. Field Sources and Usage CSV
        field_usage_data = []
        for field_name in result['all_fields']:
            data_source = result['field_sources'].get(field_name, 'Generated/Calculated')
            used = "Yes" if field_name in result['used_fields'] else "No"
            usage_reason = result['usage_reasons'].get(field_name, "")
            
            field_usage_data.append([
                field_name,
                data_source,
                used,
                usage_reason
            ])
        
        write_csv(output_folder / f"field_sources_and_usage_{flow_name}.csv",
                 ["Field Name", "Data Source", "Used", "Usage Reason"],
                 field_usage_data)
        
        # 4. Calculated Fields CSV
        calculated_fields_data = []
        for field_name, formula in result['transformations']['calculations'].items():
            calculated_fields_data.append([field_name, formula])
        
        write_csv(output_folder / f"calculated_fields_{flow_name}.csv",
                 ["Field Name", "Formula"],
                 calculated_fields_data)
        
        # 5. Renamed Fields CSV
        renamed_fields_data = []
        for new_name, old_name in result['transformations']['renames'].items():
            renamed_fields_data.append([old_name, new_name])
        
        write_csv(output_folder / f"renamed_fields_{flow_name}.csv",
                 ["Original Name", "New Name"],
                 renamed_fields_data)
        
        # 6. Transformations Summary CSV
        transformations_data = []
        
        # Add calculations
        for field_name, formula in result['transformations']['calculations'].items():
            transformations_data.append(["Calculation", field_name, formula])
        
        # Add renames
        for new_name, old_name in result['transformations']['renames'].items():
            transformations_data.append(["Rename", f"{old_name} → {new_name}", ""])
        
        # Add joins
        for join in result['transformations']['joins']:
            transformations_data.append(["Join", f"{join['left']} = {join['right']}", join['node_name']])
        
        # Add aggregations
        for field, agg_type in result['transformations']['aggregate_fields'].items():
            transformations_data.append(["Aggregation", f"{agg_type}({field})", ""])
        
        # Add group by
        for field in result['transformations']['group_by_fields']:
            transformations_data.append(["Group By", field, ""])
        
        # Add filters
        for filter_info in result['transformations']['filters']:
            transformations_data.append(["Filter", filter_info['expression'], filter_info['node_name']])
        
        write_csv(output_folder / f"transformations_summary_{flow_name}.csv",
                 ["Type", "Details", "Context"],
                 transformations_data)
        
        print(f"📁 Generated 6 CSV files in {output_folder}")
        return True
        
    except Exception as e:
        print(f"❌ Error writing CSV files: {e}")
        import traceback
        traceback.print_exc()
        return False

def write_csv(file_path, headers, data):
    """Write CSV file with proper encoding"""
    try:
        with open(file_path, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)
            writer.writerows(data)
        print(f"  ✅ Created: {file_path.name}")
    except Exception as e:
        print(f"  ❌ Error writing {file_path.name}: {e}")

def zip_output_folder(folder_path):
    """Create a zip file of the output folder"""
    try:
        zip_path = folder_path.with_suffix('.zip')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file_path in folder_path.rglob('*'):
                if file_path.is_file():
                    arc_name = file_path.relative_to(folder_path)
                    zf.write(file_path, arc_name)
        
        shutil.rmtree(folder_path)
        print(f"📦 Created zip file: {zip_path.name}")
        
    except Exception as e:
        print(f"❌ Error creating zip file: {e}")

def main():
    """Main function with comprehensive interactive interface"""
    try:
        input_dir, output_dir, database_filter, clear_output = get_user_inputs()
        
        # Setup output directory
        base_output = Path(output_dir)
        if clear_output and base_output.exists():
            shutil.rmtree(base_output)
        base_output.mkdir(parents=True, exist_ok=True)
        
        print(f"\n🚀 Starting basic analysis...")
        print(f"📁 Input directory: {input_dir}")
        print(f"📁 Output directory: {output_dir}")
        print(f"🗄️ Database filter: {database_filter or 'All databases'}")
        print("=" * 60)
        
        # Find all flow files
        input_path = Path(input_dir)
        flow_files = []
        
        for pattern in ["*.tfl", "*.tflx"]:
            flow_files.extend(input_path.rglob(pattern))
        
        if not flow_files:
            print(f"❌ No .tfl or .tflx files found in {input_dir}")
            return
        
        print(f"🔍 Found {len(flow_files)} flow files to process")
        
        # Process all files
        successful_files = 0
        failed_files = 0
        
        for i, flow_file in enumerate(flow_files, 1):
            print(f"\n📊 Processing file {i}/{len(flow_files)}: {flow_file.name}")
            
            try:
                # Create individual output folder for this flow
                flow_name = flow_file.stem
                temp_output = base_output / f"_{flow_name}"
                
                # Process the flow file
                success = extract_field_usage_with_csv(flow_file, temp_output, database_filter)
                
                if success:
                    # Zip the output folder
                    zip_output_folder(temp_output)
                    successful_files += 1
                    print(f"✅ Successfully processed: {flow_name}")
                else:
                    failed_files += 1
                    print(f"❌ Failed to process: {flow_name}")
                    # Clean up failed output folder
                    if temp_output.exists():
                        shutil.rmtree(temp_output, ignore_errors=True)
                        
            except Exception as e:
                failed_files += 1
                print(f"❌ Error processing {flow_file.name}: {str(e)}")
                # Clean up on error
                temp_output = base_output / f"_{flow_file.stem}"
                if temp_output.exists():
                    shutil.rmtree(temp_output, ignore_errors=True)
        
        # Generate summary report
        print(f"\n{'='*60}")
        print(f"📊 PROCESSING SUMMARY")
        print(f"{'='*60}")
        print(f"✅ Successfully processed: {successful_files} files")
        print(f"❌ Failed to process: {failed_files} files")
        print(f"📈 Success rate: {(successful_files/(successful_files+failed_files)*100):.1f}%" if (successful_files+failed_files) > 0 else "Success rate: 0%")
        
        if database_filter:
            print(f"🗄️ Database filter applied: {database_filter}")
        
        print(f"📁 All results saved to: {base_output}")
        
        # List generated files
        zip_files = list(base_output.glob("*.zip"))
        if zip_files:
            print(f"\n📦 Generated analysis files:")
            for zip_file in sorted(zip_files):
                print(f"  • {zip_file.name}")
        
        print(f"\n🎉 Basic analysis complete!")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Analysis interrupted by user")
    except Exception as e:
        print(f"\n❌ Critical error during analysis: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()