import hcl2
import json
import os

class TerraformParser:
    """Parse Terraform HCL files"""
    
    def parse_file(self, filepath):
        """
        Parse a single Terraform file
        
        Returns:
            List of resources with their properties
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Parse HCL
            parsed = hcl2.loads(content)
            
            resources = []
            
            # Extract resources
            if 'resource' in parsed:
                for resource_block in parsed['resource']:
                    for resource_type, resource_configs in resource_block.items():
                        for resource_name, resource_props in resource_configs.items():
                            resources.append({
                                'type': resource_type,
                                'name': resource_name,
                                'properties': resource_props,
                                'file': filepath
                            })
            
            return resources
        
        except Exception as e:
            print(f"Error parsing {filepath}: {e}")
            return []
    
    def parse_directory(self, directory):
        """
        Parse all .tf files in directory
        
        Returns:
            List of all resources found
        """
        all_resources = []
        
        for root, dirs, files in os.walk(directory):
            for file in files:
                if file.endswith('.tf'):
                    filepath = os.path.join(root, file)
                    resources = self.parse_file(filepath)
                    all_resources.extend(resources)
        
        return all_resources
    
    def extract_property(self, resource, property_path):
        """
        Extract nested property from resource
        
        Example:
            property_path = 'versioning.enabled'
            Returns value of resource['properties']['versioning']['enabled']
        """
        props = resource.get('properties', {})
        
        for key in property_path.split('.'):
            if isinstance(props, dict):
                props = props.get(key)
            elif isinstance(props, list) and props:
                props = props[0].get(key)
            else:
                return None
        
        return props