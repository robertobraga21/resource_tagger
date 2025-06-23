import boto3
import uuid
import time
import json
import io
import zipfile

# --- CONFIGURAÇÃO ---
AWS_REGION = "us-east-1"  # Mude para a sua região de preferência
RESOURCE_COUNT = 5        # Quantidade de cada tipo de recurso a ser criado
BASE_NAME = "teste-tag-app" # Nome base para os recursos
TAG_PADRAO = {"Key": "CreatedBy", "Value": "TestScript"} # Tag para fácil limpeza

# --- INICIALIZAÇÃO DOS CLIENTES BOTO3 ---
session = boto3.Session(region_name=AWS_REGION)
ec2_client = session.client("ec2")
s3_client = session.client("s3")
dynamodb_client = session.client("dynamodb")
lambda_client = session.client("lambda")
iam_client = session.client("iam")

print(f"AVISO: Este script criará {RESOURCE_COUNT} de cada tipo de recurso na região {AWS_REGION}.")
print("Pressione Enter para continuar ou CTRL+C para cancelar...")
input()

def get_latest_amazon_linux_ami():
    """Busca a AMI mais recente do Amazon Linux 2 para não hardcodar o ID."""
    print("Buscando a AMI mais recente do Amazon Linux 2...")
    try:
        response = ec2_client.describe_images(
            Owners=['amazon'],
            Filters=[
                {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
                {'Name': 'state', 'Values': ['available']},
            ]
        )
        images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
        if not images:
            print("ERRO: Nenhuma AMI do Amazon Linux 2 foi encontrada.")
            return None
        ami_id = images[0]['ImageId']
        print(f"AMI encontrada: {ami_id}")
        return ami_id
    except Exception as e:
        print(f"ERRO ao buscar AMI: {e}")
        return None

def create_lambda_execution_role(role_name):
    """Cria um papel IAM para a execução da função Lambda."""
    print(f"Criando Papel IAM: {role_name}")
    assume_role_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}]
    }
    try:
        response = iam_client.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(assume_role_policy),
            Tags=[TAG_PADRAO]
        )
        iam_client.attach_role_policy(
            RoleName=role_name,
            PolicyArn='arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
        )
        role_arn = response['Role']['Arn']
        print(f"Papel IAM criado com sucesso: {role_arn}")
        print("Aguardando 10 segundos para a propagação do papel IAM...")
        time.sleep(10)
        return role_arn
    except iam_client.exceptions.EntityAlreadyExistsException:
        print(f"Papel IAM '{role_name}' já existe. Usando o existente.")
        response = iam_client.get_role(RoleName=role_name)
        return response['Role']['Arn']
    except Exception as e:
        print(f"Erro ao criar papel IAM: {e}")
        return None

def create_resources(latest_ami_id, lambda_role_arn):
    """Função principal para orquestrar a criação dos recursos."""
    for i in range(1, RESOURCE_COUNT + 1):
        resource_name = f"{BASE_NAME}-{i}"
        print(f"\n--- Criando conjunto de recursos: {resource_name} ---")

        # 1. Instância EC2
        try:
            print(f"Criando instância EC2: {resource_name}")
            ec2_client.run_instances(
                ImageId=latest_ami_id, InstanceType="t2.nano", MinCount=1, MaxCount=1,
                TagSpecifications=[{'ResourceType': 'instance', 'Tags': [TAG_PADRAO, {'Key': 'Name', 'Value': resource_name}]}]
            )
            print("  -> Sucesso!")
        except Exception as e:
            print(f"  -> ERRO ao criar instância EC2: {e}")

        # 2. Bucket S3
        try:
            bucket_name = f"{resource_name}-{uuid.uuid4().hex[:6]}"
            print(f"Criando bucket S3: {bucket_name}")
            s3_args = {'Bucket': bucket_name}
            if AWS_REGION != 'us-east-1':
                s3_args['CreateBucketConfiguration'] = {'LocationConstraint': AWS_REGION}
            s3_client.create_bucket(**s3_args)
            s3_client.put_bucket_tagging(
                Bucket=bucket_name,
                Tagging={'TagSet': [TAG_PADRAO, {'Key': 'Name', 'Value': resource_name}]}
            )
            print("  -> Sucesso!")
        except Exception as e:
            print(f"  -> ERRO ao criar bucket S3: {e}")

        # 3. Tabela DynamoDB
        try:
            print(f"Criando tabela DynamoDB: {resource_name}")
            dynamodb_client.create_table(
                TableName=resource_name,
                KeySchema=[{'AttributeName': 'id', 'KeyType': 'HASH'}],
                AttributeDefinitions=[{'AttributeName': 'id', 'AttributeType': 'S'}],
                BillingMode='PAY_PER_REQUEST',
                Tags=[TAG_PADRAO, {'Key': 'Name', 'Value': resource_name}]
            )
            print("  -> Sucesso!")
        except Exception as e:
            print(f"  -> ERRO ao criar tabela DynamoDB: {e}")

        # 4. Volume EBS
        try:
            print(f"Criando volume EBS: {resource_name}")
            ec2_client.create_volume(
                AvailabilityZone=f"{AWS_REGION}a", Size=1, VolumeType='gp3',
                TagSpecifications=[{'ResourceType': 'volume', 'Tags': [TAG_PADRAO, {'Key': 'Name', 'Value': resource_name}]}]
            )
            print("  -> Sucesso!")
        except Exception as e:
            print(f"  -> ERRO ao criar volume EBS: {e}")

        # 5. Função Lambda
        if lambda_role_arn:
            try:
                print(f"Criando função Lambda: {resource_name}")
                
                # --- GERAÇÃO DO ZIP EM MEMÓRIA (MÉTODO ROBUSTO) ---
                dummy_code = """
import json

def handler(event, context):
    return {
        'statusCode': 200,
        'body': json.dumps('Hello from Lambda!')
    }
"""
                in_memory_zip = io.BytesIO()
                with zipfile.ZipFile(in_memory_zip, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
                    zf.writestr('index.py', dummy_code)
                
                zip_content = in_memory_zip.getvalue()
                # --- FIM DA GERAÇÃO DO ZIP ---

                lambda_client.create_function(
                    FunctionName=resource_name,
                    Runtime='python3.9',
                    Role=lambda_role_arn,
                    Handler='index.handler',
                    Code={'ZipFile': zip_content},
                    Tags={TAG_PADRAO['Key']: TAG_PADRAO['Value'], 'Name': resource_name}
                )
                print("  -> Sucesso!")
            except Exception as e:
                print(f"  -> ERRO ao criar função Lambda: {e}")

if __name__ == "__main__":
    latest_ami = get_latest_amazon_linux_ami()
    iam_role_name = f"{BASE_NAME}-lambda-role"
    lambda_role_arn = create_lambda_execution_role(iam_role_name)
    
    if latest_ami and lambda_role_arn:
        create_resources(latest_ami, lambda_role_arn)
        print("\nCriação de recursos concluída!")
        print("Lembre-se de executar o script de limpeza quando terminar os testes.")
    else:
        print("\nNão foi possível iniciar a criação de recursos devido a erros na configuração inicial.")