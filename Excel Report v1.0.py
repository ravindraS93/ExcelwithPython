import pandas as pd
import re
from datetime import datetime

print("Task Started")
print("Loading files")

# Specify the file names / paths 
file1_path = 'Asset CMDB.xlsx'
file2_path = 'Detections.xlsx'

# Read both Excel files into DataFrames(df)
df1 = pd.read_excel(file1_path)
df2 = pd.read_excel(file2_path)

# Column in df1 to perform VLOOKUP on
lookup_column= 'IP'

# Column in df2 to use as a reference for VLOOKUP
reference_column = 'IP'

# List of columns from df1 to return values to df2
return_columns = ['Env', 'STATUS', 'Operating System', 'OS Lifecycle EOL Date', 'OS Lifecycle EOS Date', 'Internet Facing', 'Asset Criticality', 'Patching Scope']

# Perform VLOOKUP and merge the DataFrames into a new dataframe
merged_df = pd.merge(df2, df1[[reference_column] + return_columns], how='left', left_on=lookup_column, right_on=reference_column)

# Columns to drop (delete unwwanted columns from the merged dataframe)
columns_to_drop = ['OS','NetBIOS', 'Port', 'Protocol', 'SSL', 'Tracking ID']

merged_df.drop(columns=columns_to_drop, inplace=True)

# Rearranging columns in the new merged dataframes
# In order to achive this, run the script by commenting out the below code. Create the list using the rearranged column headers and run the script again by removing the hash

merged_df = merged_df[['IP', 'DNS', 'Env', 'STATUS', 'Operating System', 'OS Lifecycle EOL Date', 'OS Lifecycle EOS Date', 'Internet Facing', 'Asset Criticality', 'Patching Scope', 'Title', 'Vuln Status', 'Severity', 'First Detected', 'Last Detected', 'Last Reopened', 'CVE ID', 'CVSS', 'Solution', 'Exploitability', 'Results', 'Exempted']]

print("VLOOKUP and Merging completed successfully.")

print("Performing Find and Replace Tasks")

# Dictionary of old and new values for replacement
replacement_dict = {
    'Fixed' : 'Closed',
    'Active' : 'Open',
    'New' : 'Open',
    'Reopened' : 'Open',
   # Add more entries as needed
}

# Perform the find and replace operation on the selected columns using wildcards
for old_pattern, new_value in replacement_dict.items():
    merged_df['Vuln Status'] = merged_df['Vuln Status'].replace(to_replace=old_pattern, value=new_value, regex=True)

# Replace blank cells with "No" in the specified column
merged_df['CVE ID'] = merged_df['CVE ID'].fillna('No')

# Replace non-blank values in the "Exploitability" column with "Yes" and blank values with "No"
merged_df['Exploitability'] = merged_df['Exploitability'].apply(lambda x: 'Yes' if pd.notnull(x) else 'No')

print("Performing Formulation Tasks")

# Convert date columns to datetime
merged_df['First Detected'] = pd.to_datetime(merged_df['First Detected'])
merged_df['Last Detected'] = pd.to_datetime(merged_df['Last Detected'])
merged_df['Last Reopened'] = pd.to_datetime(merged_df['Last Reopened'], errors='coerce')  # Convert to datetime and handle 'NA'

# Calculate age based on conditions
merged_df['Age'] = merged_df.apply(lambda row: (row['Last Detected'] - row['Last Reopened']).days if pd.notnull(row['Last Reopened']) else (row['Last Detected'] - row['First Detected']).days, axis=1)

# Add a new column based on the condition
merged_df['New/Old'] = merged_df['Age'].apply(lambda x: 'New' if x <= 7 else 'Old')

# Get the current date and time
current_datetime = datetime.now()

# Format the datetime to include in the filename
date_str = current_datetime.strftime("%d-%m-%Y")

# Construct the filename with the current date and time
filename = f"VMDR Report {date_str}.xlsx"

# Save the merged DataFrame back to the new Excel file
merged_df.to_excel(filename, index=False)

print("VMDR report Created Successfully")
