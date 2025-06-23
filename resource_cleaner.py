import boto3
import time

# --- CONFIGURAÇÃO ---
AWS_REGION = "us-east-1"  # Use a mesma região do script de criação
TAG_KEY = "CreatedBy"
TAG_VALUE = "TestScript"

# --- INICIALIZAÇÃO DOS CLIENTES BOTO3 ---
session = boto3.Session(region_name=AWS_REGION)
tagging_client = session.client("resourcegroupstaggingapi")
ec2_client = session.client("ec2")
s3_client = session.client("s3")
dynamodb_client = session.client("dynamodb")
lambda_client = session.client("lambda")
iam_client = session.client("iam")

def delete_resources(resources_to_delete):
    """Deleta recursos com base no seu tipo de serviço."""
    # Dicionários para agrupar recursos por tipo para exclusão em lote
    resources = {
        'ec2_instances': [], 's3_buckets': [], 'dynamodb_tables': [],
        'lambda_functions': [], 'ebs_volumes': [], 'iam_roles': []
    }
    
    print("Organizando recursos para exclusão...")
    for res in resources_to_delete:
        arn = res['ResourceARN']
        service = arn.split(':')[2]
        resource_id = arn.split('/')[-1]
        
        if service == 'ec2' and 'instance/' in arn:
            resources['ec2_instances'].append(resource_id)
        elif service == 'ec2' and 'volume/' in arn:
            resources['ebs_volumes'].append(resource_id)
        elif service == 's3':
            # Para S3, o ID é o nome do bucket, que não está no ARN
            bucket_name = res['Tags'][1]['Value'] if len(res['Tags']) > 1 else arn.split(':')[-1]
            resources['s3_buckets'].append(bucket_name)
        elif service == 'dynamodb':
            resources['dynamodb_tables'].append(resource_id)
        elif service == 'lambda':
            resources['lambda_functions'].append(resource_id)
        elif service == 'iam' and 'role/' in arn:
             resources['iam_roles'].append(resource_id)

    # A ordem da exclusão é importante para evitar erros de dependência
    
    # 1. Terminar Instâncias EC2
    if resources['ec2_instances']:
        print(f"Terminando {len(resources['ec2_instances'])} instâncias EC2...")
        ec2_client.terminate_instances(InstanceIds=resources['ec2_instances'])
        waiter = ec2_client.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=resources['ec2_instances'])
        print("Instâncias EC2 terminadas.")
        time.sleep(5) # Dar um tempo para os recursos de rede serem liberados

    # 2. Deletar Funções Lambda
    for func in resources['lambda_functions']:
        print(f"Deletando função Lambda: {func}")
        try:
            lambda_client.delete_function(FunctionName=func)
        except Exception as e:
            print(f"  -> Erro: {e}")
            
    # 3. Deletar Volumes EBS (após instâncias terminadas)
    for vol in resources['ebs_volumes']:
        print(f"Deletando volume EBS: {vol}")
        try:
            ec2_client.delete_volume(VolumeId=vol)
        except Exception as e:
            print(f"  -> Erro: {e}")

    # 4. Deletar Tabelas DynamoDB
    for table in resources['dynamodb_tables']:
        print(f"Deletando tabela DynamoDB: {table}")
        try:
            dynamodb_client.delete_table(TableName=table)
        except Exception as e:
            print(f"  -> Erro: {e}")

    # 5. Deletar Buckets S3 (precisam estar vazios)
    for bucket in resources['s3_buckets']:
        print(f"Esvaziando e deletando bucket S3: {bucket}")
        try:
            # Esvaziar o bucket primeiro
            s3_resource = session.resource('s3')
            s3_bucket = s3_resource.Bucket(bucket)
            s3_bucket.objects.all().delete()
            # Deletar o bucket
            s3_client.delete_bucket(Bucket=bucket)
        except Exception as e:
            print(f"  -> Erro: {e}")

    # 6. Deletar Papéis IAM (após as Lambdas que os usam)
    for role in resources['iam_roles']:
        print(f"Desanexando políticas e deletando papel IAM: {role}")
        try:
            # Desanexar políticas primeiro
            policies = iam_client.list_attached_role_policies(RoleName=role)['AttachedPolicies']
            for p in policies:
                iam_client.detach_role_policy(RoleName=role, PolicyArn=p['PolicyArn'])
            iam_client.delete_role(RoleName=role)
        except Exception as e:
            print(f"  -> Erro: {e}")

    print("\nProcesso de limpeza concluído.")


if __name__ == "__main__":
    print(f"Buscando todos os recursos com a tag '{TAG_KEY}={TAG_VALUE}' na região {AWS_REGION}...")
    
    paginator = tagging_client.get_paginator('get_resources')
    pages = paginator.paginate(TagFilters=[{'Key': TAG_KEY, 'Values': [TAG_VALUE]}])
    
    all_resources = []
    for page in pages:
        all_resources.extend(page['ResourceTagMappingList'])

    if not all_resources:
        print("Nenhum recurso encontrado com a tag especificada. Nada a fazer.")
    else:
        print(f"Foram encontrados {len(all_resources)} recursos para exclusão:")
        for res in all_resources:
            print(f"  - {res['ResourceARN']}")
        
        confirm = input("\nVOCÊ TEM CERTEZA que deseja deletar permanentemente todos os recursos listados acima? (digite 'sim' para confirmar): ")
        if confirm.lower() == 'sim':
            delete_resources(all_resources)
        else:
            print("Limpeza cancelada pelo usuário.")