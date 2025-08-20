# Tableau Prep Field Analysis Suite

A comprehensive toolkit for analyzing Tableau Prep flow files to understand field usage, transformations, and data lineage across all data sources including Oracle, SQL Server, PostgreSQL, MySQL, file sources (CSV, Excel), and other connections.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation & Setup](#installation--setup)
- [Quick Start](#quick-start)
- [Interactive Prompt Reference](#interactive-prompt-reference)
- [Script Versions](#script-versions)
- [Usage Examples](#usage-examples)
- [Additional Scripts](#additional-scripts)
- [Output Files](#output-files)
- [Enhanced Interactive Features](#enhanced-interactive-features)
- [Field Usage Logic](#field-usage-logic)
- [Data Source Support](#data-source-support)
- [Performance](#performance)
- [Troubleshooting](#troubleshooting)
- [Examples](#examples)
- [Support](#support)
- [License](#license)
- [Contributing](#contributing)

## 🎯 Overview

This project provides two complementary approaches for analyzing Tableau Prep flows with full support for both database and file-based data sources:

- **Basic Version**: Quick analysis with essential field tracking and comprehensive source detection
- **Enhanced Version**: Deep analysis with detailed usage reasoning, advanced transformations, and relationship mapping

Both versions process .tfl and .tflx files to extract field relationships, transformations, and usage patterns from all supported data source types.

## ✨ Features

### Core Capabilities

- 📊 **Universal Data Source Support**: Database connections AND file sources (CSV, Excel, JSON, etc.)
- 🔄 **Comprehensive Transformation Detection**: Calculations, renames, filters, joins, aggregations, unions, pivots
- 🗺️ **Complete Field Lineage Mapping**: Trace dependencies from any input source to final output
- 🎯 **Smart Table Resolution**: Automatically resolve "Unknown" table names using multiple strategies
- 📈 **Batch Processing**: Analyze multiple flows simultaneously with progress tracking
- 🔍 **Database Type Filtering**: Focus analysis on specific database types while preserving full context

### Advanced Features (Enhanced Version)

- 💡 **Detailed Usage Reasoning**: Understand exactly why each field is used with comprehensive explanations
- 🔗 **Dependency Graphs**: Visualize field relationships and transformation chains
- 📊 **Usage Pattern Analysis**: Identify common transformation patterns and complexity scoring
- 🎛️ **Deep Analysis Mode**: Comprehensive dependency tracking, metadata analysis, and relationship mapping
- 🧠 **Transitive Usage Analysis**: Track indirect field dependencies through complex transformation chains

### Data Source Intelligence

- 🗄️ **Database Sources**: Oracle, SQL Server, PostgreSQL, MySQL, Teradata, Snowflake, Redshift, BigQuery, and more
- 📁 **File Sources**: CSV, Excel (.xls/.xlsx), JSON, Text files with proper categorization
- 🌐 **Tableau Server**: Published data sources with connection analysis
- 🔌 **Custom Connections**: JDBC, ODBC, and other connection types

## 📦 Installation & Setup

### Requirements
- Python 3.7+
- Standard libraries only (csv, json, zipfile, os, pathlib, collections, re, datetime, tempfile, shutil)

### Quick Start
1. Download all scripts to a folder
2. Run any script directly - no command-line arguments needed
3. Follow the interactive prompts for guided analysis
4. All scripts are self-contained with comprehensive error handling

### No Configuration Required
- Scripts auto-detect all data source types (database and file)
- Output directories created automatically with timestamps
- Intelligent table name resolution with multiple fallback strategies
- Comprehensive progress reporting guides users through the process

## 📊 Interactive Prompt Reference

### Database Filtering Options (All Scripts)

| Option | Database Type | Description |
|--------|---------------|-------------|
| **1** | **All databases** | Analyze all database types + file sources (comprehensive analysis) |
| **2** | **Oracle only** | Filter for Oracle connections only |
| **3** | **SQL Server only** | Filter for SQL Server connections only |
| **4** | **PostgreSQL only** | Filter for PostgreSQL connections only |
| **5** | **MySQL only** | Filter for MySQL connections only |

**Note**: File sources (CSV, Excel, JSON) are properly categorized but excluded from database-specific filtering options 2-5.

### Analysis Depth Options (Enhanced Scripts Only)

| Option | Analysis Type | Features Included |
|--------|---------------|-------------------|
| **1** | **Standard analysis** | Complete field usage, transformations, basic lineage |
| **2** | **Deep analysis** | All standard features + dependency graphs, transitive usage, complexity scoring, relationship mapping |

### Clear Output Directory Options

| Option | Action | Result |
|--------|--------|--------|
| **y** | **Yes, clear** | Removes existing output directory before processing |
| **n** | **No, keep** | Preserves existing files, may overwrite individual files |

## 🚀 Usage Examples

### Basic Flow Analysis
```bash
python tableau_prep_analyzer_basic.py
```
Follow the prompts:
1. Enter directory: `/path/to/tableau/flows`
2. Output directory: `analysis_results` (or press Enter for auto-generated)
3. Database filter: **1** (All databases) or **2** (Oracle only)
4. Clear output: **y**

**Result**: Individual ZIP files for each flow with 6 comprehensive CSV files

### Enhanced Analysis with Deep Insights
```bash
python tableau_prep_analyzer_enhanced.py
```
Follow the prompts:
1. Enter directory: `/path/to/tableau/flows`
2. Output directory: (press Enter for auto-generated)
3. Database filter: **2** (Oracle only) or **1** (All sources)
4. Analysis depth: **2** (Deep analysis with dependency tracking)
5. Clear output: **n**

**Result**: Enhanced ZIP files with 8+ CSV files including complexity analysis

### Table Mapping Extraction
```bash
python extract_table_mappings_enhanced.py
```
Follow the prompts:
1. Enter file path: `/path/to/flow.tflx`
2. Output CSV: `table_mappings.csv`
3. Analysis depth: **2** (Deep analysis with relationships)

**Result**: Comprehensive table mappings with relationship analysis

### Cross-Flow Database Analysis
```bash
python database_field_aggregator_enhanced.py
```
Follow the prompts:
1. Enter directory: `/path/to/analysis/results`
2. Output file: `aggregated_database_analysis`
3. Database filter: **3** (SQL Server only)
4. Analysis depth: **2** (Deep analysis with usage patterns)

**Result**: Enterprise-level analysis across all flows with 5+ detailed reports

## 📋 Script Versions

### Basic Version Suite

#### tableau_prep_analyzer_basic.py

```bash
python tableau_prep_analyzer_basic.py
```

**Interactive prompts:**
1. Directory path containing .tfl/.tflx files
2. Output directory (optional, auto-generated with timestamp)
3. Database filtering option (**1**=All, **2**=Oracle, **3**=SQL Server, **4**=PostgreSQL, **5**=MySQL)
4. Clear output directory option (**y**=Yes, **n**=No)

**Features:**
- Comprehensive data source detection (database + file)
- Complete field lineage tracking
- Essential transformation analysis
- 6 detailed CSV outputs per flow

#### database_field_aggregator_basic.py

```bash
python database_field_aggregator_basic.py
```

**Interactive prompts:**
1. Directory path containing ZIP analysis results
2. Output CSV file name
3. Database filtering option (**1**=All, **2**=Oracle, **3**=SQL Server, **4**=PostgreSQL, **5**=MySQL)

**Features:**
- Multi-flow aggregation with intelligent table resolution
- Database vs file source discrimination
- Usage rate analysis by database type
- Comprehensive summary with resolution statistics

#### extract_table_mappings_basic.py

```bash
python extract_table_mappings_basic.py
```

**Interactive prompts:**
1. File path to .tfl/.tflx file
2. Output CSV file name (optional)

**Features:**
- Multi-method table extraction (JSON, XML, SQL patterns)
- Database type detection and categorization
- Extraction method effectiveness tracking

### Enhanced Version Suite

#### tableau_prep_analyzer_enhanced.py

```bash
python tableau_prep_analyzer_enhanced.py
```

**Interactive prompts:**
1. Directory path containing .tfl/.tflx files
2. Output directory (optional, auto-generated with timestamp)
3. Database filtering option (**1**=All, **2**=Oracle, **3**=SQL Server, **4**=PostgreSQL, **5**=MySQL)
4. Analysis depth (**1**=Standard, **2**=Deep analysis with dependency tracking)
5. Clear output directory option (**y**=Yes, **n**=No)

**Features:**
- All basic features plus advanced analytics
- Dependency graph generation and transitive analysis
- Field complexity scoring
- 8+ CSV outputs including relationship analysis

#### database_field_aggregator_enhanced.py

```bash
python database_field_aggregator_enhanced.py
```

**Interactive prompts:**
1. Directory path containing ZIP analysis results
2. Output CSV file name
3. Database filtering option (**1**=All, **2**=Oracle, **3**=SQL Server, **4**=PostgreSQL, **5**=MySQL)
4. Analysis depth (**1**=Standard, **2**=Deep analysis with usage patterns)

**Features:**
- Advanced pattern analysis and complexity scoring
- Enhanced table resolution with multiple strategies
- 5+ output files including pattern and complexity analysis
- Enterprise-level insights across all flows

#### extract_table_mappings_enhanced.py

```bash
python extract_table_mappings_enhanced.py
```

**Interactive prompts:**
1. File path to .tfl/.tflx file
2. Output CSV file name (optional)
3. Analysis depth (**1**=Standard, **2**=Deep analysis with relationship mapping)

**Features:**
- Comprehensive relationship mapping
- SQL query analysis for embedded table references
- Enhanced metadata extraction
- 4+ output files including relationship and schema analysis

## 💻 Additional Scripts

All scripts use the same interactive prompt system with consistent option numbering for ease of use across the entire suite.

## 📋 Output Files

### Main Analyzer Scripts Output

| File Pattern | Content | Basic | Enhanced |
|--------------|---------|-------|----------|
| `input_fields_[flow].csv` | All input fields with sources and metadata | ✅ | ✅ |
| `output_fields_[flow].csv` | Final output fields with data types | ✅ | ✅ |
| `field_sources_and_usage_[flow].csv` | Complete usage analysis with reasons | ✅ | ✅ |
| `calculated_fields_[flow].csv` | Calculated fields with formulas | ✅ | ✅ |
| `renamed_fields_[flow].csv` | Field rename mappings | ✅ | ✅ |
| `transformations_summary_[flow].csv` | All transformations found | ✅ | ✅ |
| `field_lineage_[flow].csv` | Complete transformation paths | ❌ | ✅ |
| `dependency_graph_[flow].csv` | Node dependencies (Deep mode) | ❌ | ✅ |
| `output_dependency_summary_[flow].csv` | Input requirements per output | ❌ | ✅ |

### Database Aggregator Output

| File Pattern | Content | Basic | Enhanced |
|--------------|---------|-------|----------|
| `[name].csv` | Main aggregated results | ✅ | ✅ |
| `[name]_summary.csv` | Table-level statistics | ✅ | ❌ |
| `[name]_table_summary.csv` | Enhanced table analysis | ❌ | ✅ |
| `[name]_database_summary.csv` | Database type breakdown | ❌ | ✅ |
| `[name]_pattern_analysis.csv` | Usage patterns (Deep mode) | ❌ | ✅ |
| `[name]_complexity_analysis.csv` | Field complexity (Deep mode) | ❌ | ✅ |
| `[name]_location_analysis.csv` | Flow location breakdown | ❌ | ✅ |

### Table Mapping Extractor Output

| File Pattern | Content | Basic | Enhanced |
|--------------|---------|-------|----------|
| `[name].csv` | Main table mappings | ✅ | ✅ |
| `[name]_summary.csv` | Extraction statistics | ✅ | ❌ |
| `[name]_database_analysis.csv` | Database type analysis | ❌ | ✅ |
| `[name]_extraction_analysis.csv` | Method effectiveness | ❌ | ✅ |
| `[name]_relationships.csv` | Table relationships (Deep mode) | ❌ | ✅ |
| `[name]_schema_analysis.csv` | Schema distribution | ❌ | ✅ |

## ✨ Enhanced Interactive Features

### Consistent User Experience
- **No Command-Line Arguments**: All scripts use guided interactive prompts with numbered options
- **Intelligent Defaults**: Auto-generated output directories with timestamps
- **Comprehensive Error Handling**: User-friendly error messages and recovery guidance
- **Progress Reporting**: Real-time updates on processing status

### Universal Data Source Support
Available in all scripts with consistent option numbering:

| Option | Filter Type | Scope |
|--------|-------------|-------|
| **1** | All sources | Complete analysis of database AND file sources |
| **2** | Oracle only | Oracle database connections only |
| **3** | SQL Server only | SQL Server database connections only |
| **4** | PostgreSQL only | PostgreSQL database connections only |
| **5** | MySQL only | MySQL database connections only |

**Note**: File sources (CSV, Excel, etc.) are properly categorized and excluded from database-specific filtering while remaining visible in comprehensive reports.

### Analysis Depth Options (Enhanced Scripts)
| Option | Analysis Level | Includes |
|--------|----------------|----------|
| **1** | Standard | Comprehensive field usage and transformation tracking |
| **2** | Deep Analysis | All standard features + dependency graphs, transitive usage, complexity scoring, relationship mapping |

### Advanced Intelligence Features
- **Smart Table Resolution**: Multiple strategies to resolve "Unknown" table names
- **Pattern Recognition**: Identifies common transformation patterns and complexity
- **Relationship Mapping**: Tracks table dependencies and data flow relationships
- **Context Awareness**: Uses file structure and naming patterns for enhanced resolution

## 🔍 Field Usage Logic

### How Fields Are Marked as "Used"

1. **Direct Output**: Fields appearing in final flow output
2. **Calculation Dependencies**: Fields referenced in calculation formulas (with transitive analysis)
3. **Transformation Participation**: Fields involved in renames, aggregations, joins, unions, pivots
4. **Filter Conditions**: Fields used in filter expressions and criteria
5. **Grouping Operations**: Fields used in GROUP BY and aggregation operations

### Enhanced Usage Tracking (Enhanced Version)

- **Transitive Dependencies**: Fields that contribute to used fields through intermediate calculations
- **Usage Pattern Categorization**: Detailed classification of how fields are used (9+ pattern types)
- **Transformation Chain Analysis**: Complete dependency tracking through multiple transformation steps
- **Complexity Scoring**: Quantitative analysis of field transformation complexity

### Source Type Handling

- **Database Sources**: Full server.schema.table resolution with connection analysis
- **File Sources**: Path-based identification with type categorization (CSV, Excel, JSON)
- **Published Sources**: Tableau Server data source tracking with metadata
- **Mixed Environments**: Proper handling of flows with multiple source types

## 🗄️ Data Source Support

### Database Systems
| Database | Detection | Connection Analysis | Schema Resolution |
|----------|-----------|-------------------|------------------|
| Oracle | ✅ | ✅ | ✅ |
| SQL Server | ✅ | ✅ | ✅ |
| PostgreSQL | ✅ | ✅ | ✅ |
| MySQL/MariaDB | ✅ | ✅ | ✅ |
| Teradata | ✅ | ✅ | ✅ |
| Snowflake | ✅ | ✅ | ✅ |
| Redshift | ✅ | ✅ | ✅ |
| BigQuery | ✅ | ✅ | ✅ |
| Databricks | ✅ | ✅ | ✅ |
| Other JDBC/ODBC | ✅ | ✅ | Limited |

### File Sources
| File Type | Detection | Metadata Extraction | Path Analysis |
|-----------|-----------|-------------------|---------------|
| CSV Files | ✅ | ✅ | ✅ |
| Excel (.xls/.xlsx) | ✅ | ✅ | ✅ |
| JSON Files | ✅ | ✅ | ✅ |
| Text Files | ✅ | ✅ | ✅ |
| Parquet | ✅ | Limited | ✅ |

### Published Sources
| Source Type | Detection | Metadata | Relationship Tracking |
|-------------|-----------|----------|---------------------|
| Tableau Server | ✅ | ✅ | ✅ |
| Tableau Online | ✅ | ✅ | ✅ |
| Published Extracts | ✅ | Limited | ✅ |

## ⚡ Performance

### Typical Processing Times
- **Small flows** (< 10 nodes): 1-3 seconds
- **Medium flows** (10-50 nodes): 5-20 seconds  
- **Large flows** (50+ nodes): 30-90 seconds
- **Complex flows** (100+ nodes): 2-5 minutes
- **Batch processing**: 3-8 seconds per flow

### Memory Usage
- **Basic analysis**: 50-150 MB per flow
- **Enhanced analysis**: 100-300 MB per flow
- **Deep analysis mode**: 200-500 MB per flow
- **Batch processing**: Scales linearly with concurrent flows

### Optimization Features
- **Intelligent file prioritization**: Process most important files first
- **Memory cleanup**: Automatic cleanup of temporary files and data
- **Progress checkpoints**: Resume capability for interrupted large batch jobs
- **Parallel processing**: Multi-threaded analysis for large datasets (Enhanced version)

## 🔧 Troubleshooting

### Common Issues

#### File Processing Issues
- **Corrupted .tflx files**: Verify files can be opened in Tableau Prep Builder
- **Permission errors**: Check file and directory access permissions
- **Encoding issues**: Ensure files use UTF-8 encoding

#### Interactive Prompt Issues
- **Invalid option selection**: Enter only the number (1-5 for database options, 1-2 for analysis depth)
- **File path errors**: Use full paths and ensure no trailing spaces
- **Output directory creation**: Ensure write permissions in the target location

#### Data Source Recognition
- **"Unknown" tables**: Scripts include multiple resolution strategies
- **Missing connections**: Verify flow files contain complete connection information
- **File vs database confusion**: Check data source categorization in results

#### Performance Issues
- **Large file processing**: Consider processing files individually
- **Memory constraints**: Use Basic version (option **1**) for resource-limited environments
- **Network drives**: Copy files locally for better performance

#### Output Questions
- **Missing fields**: Review field usage logic and check for nested transformations
- **Incorrect usage determination**: Verify field appears in calculations or output
- **Empty results**: Check database filtering settings (options **1-5**) and source types

### Database-Specific Troubleshooting

#### Oracle Issues
- **Connection string parsing**: Verify TNS names and service identifiers
- **Schema resolution**: Check for case-sensitive schema names
- **SID vs Service Name**: Both formats supported in connection analysis

#### SQL Server Issues
- **Instance names**: Properly handles named instances (server\instance)
- **Integrated authentication**: Detects Windows authentication connections
- **Database vs schema**: Correctly parses database.schema.table hierarchy

#### File Source Issues
- **Path recognition**: Handles both absolute and relative file paths
- **Network drives**: UNC paths supported with proper escaping
- **File type detection**: Uses both extension and content analysis

## 📊 Examples

### Example 1: Single Database Analysis

```bash
# Analyze Oracle flows only
python tableau_prep_analyzer_enhanced.py
# Directory: /flows/oracle_migration
# Output: (auto-generated)
# Filter: 2 (Oracle only)
# Depth: 2 (Deep analysis)
# Clear: y

# Result: Detailed Oracle-specific analysis with dependency tracking
```

### Example 2: Cross-Database Migration Analysis

```bash
# Before migration - analyze current state
python tableau_prep_analyzer_basic.py
# Directory: /flows/current_state
# Output: before_migration
# Filter: 1 (All databases)
# Clear: y

# Aggregate results
python database_field_aggregator_basic.py
# Directory: before_migration
# Output: pre_migration_analysis
# Filter: 1 (All databases)

# After migration - analyze new state
python tableau_prep_analyzer_basic.py
# Directory: /flows/migrated
# Output: after_migration
# Filter: 3 (SQL Server only)
# Clear: y

# Compare results for migration validation
```

### Example 3: Table Discovery and Relationship Mapping

```bash
# Extract comprehensive table mappings
python extract_table_mappings_enhanced.py
# File: /flows/complex_flow.tflx
# Output: table_relationships.csv
# Depth: 2 (Deep analysis)

# Result: Complete table inventory with relationships
```

### Example 4: Usage Pattern Analysis

```bash
# Enhanced analysis for pattern identification
python tableau_prep_analyzer_enhanced.py
# Directory: /flows/data_warehouse
# Filter: 1 (All databases)
# Depth: 2 (Deep analysis)
# Clear: n

# Aggregate with pattern analysis
python database_field_aggregator_enhanced.py
# Directory: [results from above]
# Output: usage_patterns_analysis
# Filter: 1 (All databases)
# Depth: 2 (Deep analysis)

# Result: Comprehensive usage patterns and complexity analysis
```

### Example 5: File vs Database Source Analysis

```bash
# Analyze mixed environment (files + databases)
python tableau_prep_analyzer_basic.py
# Directory: /flows/mixed_sources
# Filter: 1 (All sources)
# Clear: y

# Result: Proper categorization of file vs database sources
```

### Example 6: Batch Processing Multiple Projects

```bash
# Process multiple projects with database filtering
for project in sales marketing finance; do
    echo "Processing $project..."
    python tableau_prep_analyzer_enhanced.py
    # Directory: ${project}_flows
    # Output: ${project}_results
    # Filter: 2 (Oracle only)
    # Depth: 1 (Standard)
    # Clear: y
done

# Aggregate each project
for project in sales marketing finance; do
    python database_field_aggregator_basic.py
    # Directory: ${project}_results
    # Output: ${project}_oracle_summary
    # Filter: 2 (Oracle only)
done

# Result: Separate Oracle analysis for each project
```

### Example 7: Quick Reference for Common Tasks

| Task | Script | Key Options |
|------|--------|-------------|
| Quick analysis of all sources | `tableau_prep_analyzer_basic.py` | Filter: **1**, Clear: **y** |
| Deep Oracle-only analysis | `tableau_prep_analyzer_enhanced.py` | Filter: **2**, Depth: **2** |
| Aggregate SQL Server results | `database_field_aggregator_basic.py` | Filter: **3** |
| Extract table relationships | `extract_table_mappings_enhanced.py` | Depth: **2** |
| Mixed source analysis | Any analyzer | Filter: **1** (includes files + databases) |

## 📞 Support

### Processing Issues

#### File Access Problems
- Ensure .tfl/.tflx files are accessible and not locked by Tableau Prep
- Verify directory permissions for input and output locations
- Check available disk space for output generation

#### Interactive Prompt Support
- **Database filtering**: Use options **1-5** as shown in reference table
- **Analysis depth**: Use **1** for standard, **2** for deep analysis (Enhanced scripts only)
- **File paths**: Use complete paths without quotes unless paths contain spaces
- **Output options**: Use **y** to clear existing directories, **n** to preserve

#### Performance Optimization
- Use Basic version for quick analysis of large datasets
- Process files individually if batch processing is slow
- Monitor system resources during large batch operations

#### Analysis Questions
- Review field usage logic section for methodology understanding
- Check console output for detailed processing information
- Validate results against original flows in Tableau Prep Builder

### Database-Specific Support

#### Multi-Database Environments
- **Complete Visibility**: Use option **1** (All databases) for comprehensive analysis across all source types
- **Focused Analysis**: Use specific database filters (**2**=Oracle, **3**=SQL Server, etc.) for targeted analysis
- **Migration Planning**: Compare before/after analyses using different database type filters
- **Performance Tuning**: Identify unused fields per database type for optimization

#### Table Resolution Issues
- **Unknown Tables**: Scripts use multiple resolution strategies including pattern matching and context analysis
- **Schema Conflicts**: Review schema analysis output for conflicts and inconsistencies
- **Connection Parsing**: Check connection string analysis in detailed outputs

### Output Interpretation

#### Usage Analysis
- **Field Marked as Used**: Field contributes to output or transformations (see Field Usage Logic)
- **Field Marked as Unused**: Field loaded but doesn't contribute to final output
- **Transitive Usage**: Field used indirectly through calculations (Enhanced version with Depth **2** only)

#### Database vs File Sources
- **Database Sources**: Show as "DatabaseType: server.schema.table"
- **File Sources**: Show as "FileType: /path/to/file.ext"
- **Published Sources**: Show as "Tableau Server: datasource_name"

#### Option Reference Quick Guide
| When You See | Valid Responses | Meaning |
|---------------|----------------|---------|
| "Enter your choice (1-5)" | **1**, **2**, **3**, **4**, or **5** | Database filtering options |
| "Enter your choice (1-2)" | **1** or **2** | Analysis depth (Enhanced scripts) |
| "Clear output directory? (y/n)" | **y** or **n** | Output directory handling |

## 📄 License

This project is provided as-is for analytical purposes. Please ensure compliance with your organization's data governance policies when analyzing production flows.

**Data Privacy**: The scripts analyze flow structure and metadata but do not access or store actual data values.

## 🤝 Contributing

This toolkit is designed to be extensible and welcomes contributions.

---
**Version**: 2.1  
**Last Updated**: December 2024  
**Compatibility**: Tableau Prep 2018.1+ flow files  
**Python Requirements**: 3.7+  
**Status**: Production Ready  

**Quick Reference**: Use option **1** for comprehensive analysis, options **2-5** for database-specific filtering, and option **2** for deep analysis in Enhanced scripts.

**Support**: For issues, feature requests, or contributions, please review the troubleshooting section and interactive prompt reference tables above.

