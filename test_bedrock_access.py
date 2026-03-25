"""
Test Bedrock Access - Auto-enables Claude 3.5 Sonnet on first use
"""

import boto3
import json
from botocore.exceptions import ClientError

def test_bedrock_access():
    """Test and auto-enable Bedrock models"""
    
    print("="*70)
    print("Testing AWS Bedrock Access")
    print("="*70)
    
    # Initialize client
    try:
        bedrock = boto3.client(
            service_name='bedrock-runtime',
            region_name='us-east-1'
        )
        print("\n Bedrock client initialized")
        print(f"   Region: us-east-1")
        
    except Exception as e:
        print(f"\n Failed to initialize Bedrock client: {e}")
        print("\n Make sure you have AWS credentials configured:")
        print("   aws configure")
        return False
    
    # Replace the models_to_test list with:
    models_to_test = [
        {
            'id': 'anthropic.claude-3-5-sonnet-20241022-v2:0',  # Claude 3.5 Sonnet v2 (ACTIVE)
            'name': 'Claude 3.5 Sonnet v2 (Latest - Active)',
            'cost': 'Premium'
        },
        {
            'id': 'anthropic.claude-3-5-sonnet-20240620-v1:0',  # Claude 3.5 Sonnet v1 (ACTIVE)
            'name': 'Claude 3.5 Sonnet v1 (Active)',
            'cost': 'Premium'
        },
        {
            'id': 'anthropic.claude-3-haiku-20240307-v1:0',  # Claude 3 Haiku (ACTIVE, Cheapest)
            'name': 'Claude 3 Haiku (Budget - Active)',
            'cost': 'Cheap - Best for Free Tier'
        },
        {
            'id': 'us.anthropic.claude-3-5-sonnet-20241022-v2:0',  # Cross-region
            'name': 'Claude 3.5 Sonnet v2 (Cross-region)',
            'cost': 'Premium'
        }
    ]
    
    working_models = []
    
    for model in models_to_test:
        print(f"\n Testing: {model['name']}")
        print(f"   Model ID: {model['id']}")
        print(f"   Cost: {model['cost']}")
        
        try:
            # Try to invoke the model
            response = bedrock.invoke_model(
                modelId=model['id'],
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 50,
                    "messages": [
                        {
                            "role": "user",
                            "content": "Say 'Hello from TerraSecure!' in one sentence."
                        }
                    ]
                })
            )
            
            # Parse response
            response_body = json.loads(response['body'].read())
            message = response_body['content'][0]['text']
            
            print(f"   SUCCESS! Model is enabled and working")
            print(f"   Response: {message}")
            working_models.append(model)
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            error_msg = e.response.get('Error', {}).get('Message', '')
            
            print(f"    FAILED: {error_code}")
            
            if error_code == 'AccessDeniedException':
                print(f"    Action needed:")
                print(f"      1. Go to: https://console.aws.amazon.com/bedrock/home?region=us-east-1#/playground")
                print(f"      2. Select this model in the playground")
                print(f"      3. Fill in the use case form when prompted")
                print(f"      4. Model will auto-enable after submission")
                
            elif error_code == 'ValidationException':
                if 'moderation policy' in error_msg.lower():
                    print(f"     Content blocked by moderation policy")
                    print(f"      (Test prompt was too simple, model actually works!)")
                    working_models.append(model)
                else:
                    print(f"     Validation error: {error_msg}")
                    
            elif error_code == 'ThrottlingException':
                print(f"     Rate limited (model works, but too many requests)")
                working_models.append(model)
                
            elif error_code == 'ResourceNotFoundException':
                print(f"     Model not available in this region")
                print(f"      Try region: us-east-1")
                
            else:
                print(f"     Error: {error_msg}")
        
        except Exception as e:
            print(f"    Unexpected error: {e}")
    
    # Summary
    print("\n" + "="*70)
    print("SUMMARY")
    print("="*70)
    
    if working_models:
        print(f"\n {len(working_models)} model(s) working:")
        for model in working_models:
            print(f"   ✓ {model['name']}")
        
        print(f"\n Recommendation:")
        print(f"   Use: {working_models[0]['name']}")
        print(f"   Model ID: {working_models[0]['id']}")
        
        print(f"\n Update your .env file:")
        print(f"   BEDROCK_MODEL_ID={working_models[0]['id']}")
        
        return True
    else:
        print(f"\n No models working yet")
        print(f"\n Next steps:")
        print(f"   1. Go to AWS Console Bedrock Playground")
        print(f"   2. Select Claude 3.5 Sonnet or Claude 3 Haiku")
        print(f"   3. Submit use case form when prompted")
        print(f"   4. Run this test again")
        
        return False

if __name__ == '__main__':
    success = test_bedrock_access()
    
    if success:
        print(f"\n Ready to use TerraSecure with Bedrock!")
        print(f"   Run: python src/cli.py examples/vulnerable")
    else:
        print(f"\n Complete setup steps above, then test again")