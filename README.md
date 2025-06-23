# **Documentação Técnica – Gerenciador de Tags AWS v9.2**

## **1\. Visão Geral**

O **Gerenciador de Tags AWS** é uma ferramenta de desktop com interface gráfica (GUI) desenvolvida em Python para facilitar o gerenciamento de tags em recursos da Amazon Web Services (AWS). A aplicação permite que os usuários listem, filtrem e modifiquem tags de forma individual ou em massa, servindo como um centralizador eficiente para garantir a governança e organização de recursos na nuvem.

**Principais Funcionalidades:**

* Visualização do ID e Alias da conta AWS ativa.  
* Listagem e busca de recursos por tags ou pela ausência delas.  
* Filtragem de buscas por uma lista abrangente de serviços específicos da AWS (EC2, S3, EKS, etc.).  
* Adição, edição e remoção de tags em recursos individuais através de seu ARN.  
* Aplicação e remoção de tags em massa para todos os recursos resultantes de uma busca.  
* Tagueamento de múltiplas tags por recurso via upload de um arquivo CSV.  
* Validações de segurança para prevenir operações em contas ou recursos inexistentes, tanto em ações manuais quanto em massa.

## **2\. Pré-requisitos e Instalação**

Antes de executar a aplicação, certifique-se de que o ambiente esteja devidamente configurado.

### **Credenciais AWS e Permissões IAM**

A ferramenta utiliza as credenciais da AWS configuradas no ambiente de execução. A maneira mais comum e recomendada é através do **AWS CLI**.

1. **Instale o AWS CLI:** Siga as instruções no [Guia Oficial da AWS](https://aws.amazon.com/cli/).  
2. **Configure as Credenciais:** Execute o comando no seu terminal e insira suas credenciais (Access Key ID, Secret Access Key), região padrão e formato de saída.  
   aws configure

3. **Permissões IAM:** O usuário ou a role IAM associada a essas credenciais precisa de permissões para executar as ações da ferramenta. Para total funcionalidade, as seguintes permissões (ou políticas equivalentes) são necessárias:  
   * resource-groups:SearchResources  
   * resource-groups:GetResources  
   * resource-groups:TagResources  
   * resource-groups:UntagResources  
   * sts:GetCallerIdentity  
   * iam:ListAccountAliases

Para um ambiente de testes, a política gerenciada pela AWS ReadOnlyAccess é um bom começo para as funções de listagem, e PowerUserAccess para as funções de modificação.

### **Dependências Python**

O script foi desenvolvido em Python 3\. A única dependência externa necessária é a biblioteca boto3.

1. **Python:** Certifique-se de ter o Python 3.8 ou superior instalado.  
2. **Instalação do Boto3:** Abra seu terminal ou prompt de comando e execute:  
   pip install boto3

   As outras bibliotecas utilizadas (tkinter, threading, queue, csv) fazem parte da biblioteca padrão do Python e não requerem instalação.

## **3\. Execução da Aplicação**

1. Salve o código do programa em um arquivo com a extensão .py, por exemplo: gerenciador\_tags\_aws.py.  
2. Abra um terminal ou prompt de comando.  
3. Navegue até o diretório onde você salvou o arquivo.  
4. Execute o seguinte comando:  
   python3 gerenciador_tags_aws.py

A janela principal do programa deverá aparecer na tela.

## **4\. Manual de Uso das Funcionalidades**

A interface é dividida em quatro áreas principais.

### **Painel de Informações da Conta**

* Localizado no topo, este painel exibe automaticamente o **ID da Conta** e o **Nome (Alias)** da conta AWS associada às credenciais em uso. Serve como uma confirmação visual crítica para o usuário saber onde está operando.

### **Painel de Ações e Filtros**

* **Ação:** Menu dropdown para selecionar a operação principal (ex: Buscar com Tag, Adicionar/Editar Tags).  
* **Filtrar por Serviço:** Permite restringir as operações de busca (Listar, Buscar com/sem Tag) a um serviço específico da AWS. A opção padrão é Todos os Serviços.  
* **Chave da Tag / Valor da Tag:** Campos para inserir os detalhes da tag para as operações.  
* **ARN do Recurso:** Campo para inserir o ARN de um recurso específico para as ações manuais de Adicionar/Editar Tags e Remover Tags.  
* **Botões:**  
  * Executar Ação: Inicia a operação selecionada no menu "Ação".  
  * Limpar Lista: Limpa o painel de resultados e a memória de recursos listados.  
  * Carregar Planilha...: Abre uma janela para selecionar um arquivo CSV para tagueamento em massa.

### **Painel de Ações em Massa**

* Esta seção contém ações que operam sobre a lista de recursos exibida no painel de resultados. **Estes botões só ficam ativos após uma busca retornar resultados.**  
* **Texto de Ajuda:** Um pequeno texto explica o propósito desta seção.  
* **Botões:**  
  * Aplicar Tag à Lista: Usa os campos "Chave da Tag" e "Valor da Tag" e aplica essa tag a todos os recursos listados.  
  * Remover Tag da Lista: Usa o campo "Chave da Tag" e remove a tag com essa chave de todos os recursos listados.

### **Painel de Resultados**

* Uma grande área de texto com rolagem que exibe em tempo real o log de todas as operações, incluindo os recursos encontrados, mensagens de sucesso e relatórios de erro detalhados.

### **Fluxo de Tagueamento via CSV**

A função de Carregar Planilha... espera um arquivo CSV com o seguinte formato:

* **Cabeçalhos:** O arquivo deve conter as colunas arn e tags.  
* **Delimitador de Coluna:** O programa detecta automaticamente se o separador de colunas é vírgula (,) ou ponto e vírgula (;).  
* **Formato da Coluna tags:**  
  * Múltiplas tags devem ser listadas na mesma célula.  
  * Cada par de tag deve seguir o formato Chave=Valor.  
  * Os pares de tags devem ser separados pelo caractere pipe (|).

**Exemplo de tags.csv:**

arn,tags  
arn:aws:ec2:us-east-1:123456789012:instance/i-0123abc,Projeto=Netuno|Ambiente=Producao|Backup=Diario  
arn:aws:s3:::meu-bucket-teste-123,Departamento=Financeiro|Sensibilidade=Confidencial

## **5\. Detalhes Técnicos do Código**

### **Estrutura do Projeto**

O projeto consiste em um único arquivo Python (.py) que utiliza as seguintes bibliotecas principais:

* **tkinter**: Para a construção de toda a interface gráfica (GUI).  
* **boto3**: O SDK oficial da AWS para Python, usado para interagir com as APIs da AWS.  
* **threading**: Para executar operações de API demoradas em segundo plano, mantendo a interface responsiva e evitando que ela "congele".  
* **queue**: Para comunicação segura entre as threads de trabalho e a thread principal da GUI.  
* **csv**: Para a leitura e análise de arquivos CSV na funcionalidade de upload.

### **Arquitetura do Código**

O código é estruturado em duas partes principais: funções de lógica AWS e a classe da aplicação GUI.

#### **Funções Globais de Lógica AWS**

* Funções como listar_todos_recursos, adicionar_ou_editar_tags, etc., são definidas fora da classe principal.  
* Elas contêm a lógica de negócio pura, encapsulando as chamadas diretas ao cliente boto3.client('resourcegroupstaggingapi').  
* Recebem a output_queue como argumento para reportar o progresso e os resultados de volta para a interface.

#### **Classe Principal App(tk.Tk)**

* Esta classe herda de tk.Tk e representa a janela principal da aplicação. Ela gerencia todos os widgets e o estado do programa.  
* **Métodos \_create\_\*\_frame**: A interface é construída de forma modular. Cada seção principal da janela tem seu próprio método de criação (\_create\_account\_info\_frame, \_create\_controls\_frame, etc.), o que organiza o código de layout.  
* **Lógica de Eventos e Threads (start\_\*\_thread)**:  
  * Este é o padrão arquitetural central da aplicação. Para cada ação do usuário que envolve uma chamada de API, existe um método start\_\*\_thread.  
  * Este método é responsável por:  
    1. Ler e validar as entradas dos campos da GUI.  
    2. Executar validações de segurança (ID da conta, existência do recurso).  
    3. Desabilitar os botões para prevenir cliques duplos.  
    4. Criar e iniciar um novo threading.Thread, passando a função de lógica AWS correspondente como alvo (target) e os argumentos necessários (args).  
* **Comunicação Thread-GUI (output\_queue e process\_queue)**:  
  * As threads de trabalho nunca atualizam a GUI diretamente. Em vez disso, elas colocam mensagens de string em uma queue.Queue (self.output\_queue).  
  * O método process\_queue é executado em um loop na thread principal da GUI (usando self.after). Ele verifica a fila em busca de novas mensagens e, se encontrar, as escreve de forma segura na área de resultados através do método \_write\_to\_results.  
* **Gerenciamento de Estado (self.last\_listed\_arns)**:  
  * Esta lista de instância armazena os ARNs da última operação de busca bem-sucedida.  
  * Ela é a "memória" que permite que os botões de "Ações em Massa" saibam sobre quais recursos devem operar. É populada pelas funções de busca e lida pelas funções de aplicação/remoção em massa.