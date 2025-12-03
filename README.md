# Introdução às Redes e à Internet

## Aula 01 : Conceitos fundamentais de redes de computadores

### Redes de Computadores: Visão Geral
- Redes conectam dispositivos para comunicação e compartilhamento de recursos (arquivos, impressoras, Internet).
- Essenciais na vida moderna, comparáveis à eletricidade.
- Benefícios: eficiência, conveniência, escalabilidade e redundância.

### Conceitos Básicos de Redes
- Sistema que permite troca de dados e uso compartilhado de recursos.
- Facilita comunicação rápida, acesso à Internet e distribuição de serviços empresariais.

### Topologias de Rede
- Definem como dispositivos estão conectados e influenciam fluxo e resiliência.
- **Estrela:** todos conectados a ponto central; falha de um dispositivo não afeta a rede, mas falha do ponto central derruba tudo.
- **Barramento:** todos compartilham um cabo; simples, porém vulnerável a falhas.
- **Anel:** dispositivos formam loop; eficiente, mas falha em um dispositivo interrompe comunicação.
- **Malha:** cada dispositivo conectado a todos; alta confiabilidade, porém complexa e cara.

### Comunicação em Rede e Protocolos
- Troca de dados entre dispositivos interconectados.
- Elementos: emissor, receptor, dados, meio de comunicação e protocolos (exemplo: TCP/IP).
- Protocolos garantem entendimento entre dispositivos diversos.

### Escalabilidade em Redes
- Capacidade de crescer sem perda de desempenho.
- Princípios: arquitetura adequada, redundância, balanceamento de carga, virtualização, monitoramento.
- Aplicações: expansão de varejo, data centers, provedores de Internet.

### História da Internet e ARPANET
- Internet originada na ARPANET (anos 1960), rede para pesquisadores e alta resiliência.
- Transição para TCP/IP na década de 1980.
- Internet comercial na década de 1990 com a Web de Tim Berners-Lee.
- Crescimento rápido de ISPs e comércio eletrônico.

### Web 2.0 e Experiência do Usuário
- Segunda geração da web: mais interativa, colaborativa e dinâmica.
- Exemplos: redes sociais, YouTube, Wikipedia, blogs.
- Democratização da publicação; folksonomia (classificação por tags).
- Explosão do acesso móvel.
- Surgimento das áreas UX (experiência do usuário) e UI (interface do usuário).

### Web 3.0 e Web Semântica
- Visão de uma web mais inteligente, que entende o significado dos dados.
- Web Semântica: anota dados com metadados e ontologias para compreensão automática.
- IA personaliza serviços; assistentes virtuais populares.
- Futuro: maior impacto em comércio, educação, saúde, IoT e blockchain.

# Aula 02:  Protocolos de comunicação em Redes

## Protocolos de Comunicação em Redes

### Definição e Importância
- Protocolos são regras e convenções que permitem a troca de informações entre dispositivos e sistemas.
- Funcionam como uma "linguagem comum" para que dispositivos distintos possam se entender.
- São fundamentais para o funcionamento da internet, redes locais e sistemas digitais.
- Garantem a entrega correta, segura e eficiente dos dados, evitando erros e perdas.

### Tipos de Protocolos
- **Protocolos de Rede:** Atuam na camada de rede, garantem o roteamento, endereçamento IP e encapsulamento dos dados. Exemplo: TCP/IP.
- **Protocolos de Transporte:** Gerenciam a comunicação ponto a ponto. Exemplo:
  - TCP: Confiável, confirma entrega, mantém ordem dos pacotes.
  - UDP: Focado em velocidade, não confirma entrega, usado em streaming e videoconferências.
- **Protocolos de Aplicação:** Facilitam interação entre aplicativos e serviços. Exemplos:
  - HTTP: Transferência de páginas web.
  - SMTP: Envio de e-mails.
  - FTP: Transferência de arquivos.

### RFCs (Request for Comments)
- Documentos técnicos que descrevem padrões, protocolos e procedimentos para a internet.
- Produzidos e mantidos pela IETF (Internet Engineering Task Force).
- Garantem interoperabilidade e evolução da internet.
- Servem como referência autoritária para implementações e solução de problemas.
- Exemplos importantes: RFC 793 (TCP), RFC 768 (UDP), RFC 7231 (HTTP), RFC 5321 (SMTP), RFC 959 (FTP).

### Estrutura dos Protocolos
- Incluem cabeçalhos (informações sobre origem, destino, controle de fluxo, identificação do protocolo).
- Mensagens organizadas em campos de dados com formato previsto.
- Mecanismos para garantir a integridade dos dados, sequenciamento, confirmação, retransmissão e correção de erros.

### Protocolos de Segurança na Comunicação Online
- **SSL/TLS**: Protocolos que criam uma camada segura para transmissão de dados.
- Garantem criptografia que torna os dados ilegíveis a interceptadores.
- Protegem privacidade, autenticidade do servidor e integridade dos dados.
- Protegem contra ataques como interceptação e “man-in-the-middle”.

### Importância da Proteção dos Dados
- Proteção contra roubo de identidade, fraudes financeiras e vazamentos empresariais.
- Cumprimento de regulamentações e leis de proteção de dados.
- Essencial para transações financeiras seguras e privacidade na comunicação online.

### Lei Geral de Proteção de Dados (LGPD)
- Legislação brasileira que regula coleta, armazenamento, tratamento e transferência de dados pessoais.
- Concede direitos aos indivíduos (acesso, correção, exclusão de dados).
- Exige transparência e responsabilidade das organizações.
- Requer consentimento explícito para uso dos dados.
- Prevê penalidades para quem não cumprir a lei.
- Alinha o Brasil aos regulamentos internacionais de proteção de dados.


# Aula 03: Endereçamento de IP, Sub-redes e Portas

## Endereçamento IP, Sub-redes e Portas (Aula 03)

### IPv4: Estrutura e Limitações
- Endereço IPv4: 4 octetos decimais (0-255), ex: 192.168.1.1 (~4,3 bilhões de combinações).
- **Estrutura:**
  - Endereço de rede: bits iniciais identificam a rede.
  - Máscara de sub-rede: separa rede (1s) de hosts (0s).
  - Endereço broadcast: último da faixa, envia para todos os dispositivos.
- **Classes de endereços IPv4:**
  | Classe | Uso | Octetos Rede/Host | Exemplo |
  |--------|-----|-------------------|---------|
  | A      | Grandes redes | 1/3 | 10.x.x.x (privada) |
  | B      | Empresas médias | 2/2 | 172.16.x.x (privada) |
  | C      | Pequenas redes | 3/1 | 192.168.x.x (privada) |
- **Endereços privados:** 10.0.0.0-10.255.255.255; 172.16.0.0-172.31.255.255; 192.168.0.0-192.168.255.255.
- Problema: esgotamento de endereços devido ao crescimento da Internet.
### IPv6: Solução para o Futuro
- Endereço: 128 bits em hexadecimal, ex: 2001:0db8:85a3::8a2e:370:7334 (compressão de zeros).
- **Estrutura:** 64 bits rede + 64 bits host.
- **Vantagens:**
  - Espaço praticamente infinito de endereços.
  - IPsec nativo (segurança).
  - Configuração automática de endereços.
  - Suporte a QoS (priorização de tráfego).
  - Melhor desempenho e simplicidade.
### Máscaras de Sub-rede e Segmentação
- Máscara: filtra bits de rede (1s) vs hosts (0s).
- **Segmentação de redes:** divide rede grande em sub-redes menores.
- **Benefícios:**
  - Melhor desempenho (tráfego local).
  - Maior segurança (barreiras lógicas).
  - Controle granular de tráfego.
  - Organização e redução de conflitos de IP.
### Ferramentas de Análise de Rede
- **Ping:** testa conectividade e mede latência (tempo ida/volta).
- **Traceroute:** rastreia rota dos pacotes, identifica gargalos.
- **Identificação de IP local:**
  - Windows: `ipconfig`
  - Linux: `ifconfig` ou `ip addr`
  - Online: sites "Qual é meu IP?".
### Portas de Rede
- Portas: números (1-65535) que identificam serviços em um IP.
- **Categorias:**
  | Categoria | Faixa | Exemplos |
  |-----------|-------|----------|
  | Bem conhecidas | 0-1023 | HTTP(80), HTTPS(443), SMTP(25), DNS(53), SSH(22) |
  | Registradas | 1024-49151 | Aplicativos específicos |
  | Dinâmicas | 49152-65535 | Conexões temporárias |
- Combinação IP+porta garante entrega ao serviço correto.
### Firewalls e Controle de Tráfego
- **Funções do firewall:**
  - Filtragem de pacotes (regras baseadas em IP/porta/protocolo).
  - NAT: múltiplos dispositivos compartilham 1 IP público.
  - Proxy: intermediário para segurança extra.
  - Detecção de intrusão e suporte a VPN.
- **Bloqueio de portas por ISPs:** comum por segurança; contate provedor para desbloqueio.

# Aula 4: Serviços e Aplicações na Internet

### APIs e Integração de Sistemas
- **APIs (Application Programming Interfaces):** regras e protocolos que permitem comunicação entre aplicativos e sistemas.
- **Funcionamento:**
  - Cliente envia **request** (GET/POST/PUT/DELETE) → API processa → retorna **response** (JSON/XML).
  - Atuam como "intermediárias" para compartilhar dados e funcionalidades.

### Web Services e Protocolos

#### SOAP (Simple Object Access Protocol)
| Característica                   | Vantagens                           | Aplicações                                |
| -------------------------------- | ----------------------------------- | ----------------------------------------- |
| Baseado em XML, estrutura rígida | Alta segurança, transações robustas | Ambientes corporativos, sistemas críticos |
#### REST (Representational State Transfer)
| Característica                               | Vantagens                     | Aplicações                      |
| -------------------------------------------- | ----------------------------- | ------------------------------- |
| Leve, usa métodos HTTP (GET/POST/PUT/DELETE) | Simples, escalável, eficiente | APIs públicas, apps móveis, IoT |
#### Comparação SOAP vs REST
| Critério     | SOAP                 | REST                                     |
| ------------ | -------------------- | ---------------------------------------- |
| Complexidade | Alta (XML pesado)    | Baixa (HTTP simples)                     |
| Desempenho   | Mais lento           | Mais rápido                              |
| Segurança    | Integrada            | Via HTTPS/tokens                         |
| Casos de uso | Corporativo complexo | Web aberta/móvel                         |
### Arquitetura de Microsserviços
- **Conceito:** aplicação dividida em pequenos serviços independentes, cada um com função específica.
- **Características principais:**
  - Desacoplamento total entre serviços
  - Tecnologias diferentes por serviço
  - Escalabilidade individual
  - Implantação independente
  - Alta resiliência a falhas.
#### Vantagens vs Desafios
| Vantagens               | Desafios                                                     |
| ----------------------- | ------------------------------------------------------------ |
| Flexibilidade/agilidade | Complexidade de comunicação                                  |
| Escalabilidade seletiva | Gerenciamento/orquestração                                   |
| Manutenção simplificada | Testes/monitoramento complexos                               |
| Resistência a falhas    | Necessita APIs REST para comunicação.                        |

### Web 2.0: Aplicativos Interativos
- **AJAX:** comunicação assíncrona (sem recarregar página), experiência fluida.
- **Exemplos clássicos:**
  | Aplicativo | Inovação |
  |------------|----------|
  | Google Maps | Zoom, direções, Street View |
  | Gmail | Interface AJAX rápida |
  | YouTube | Upload/compartilhamento vídeo |
  | Trello | Colaboração em tempo real|

### Autenticação e Segurança em Serviços Web
- **Princípios básicos (CIA Triad):**
  - **Confidencialidade:** proteção contra acesso não autorizado
  - **Integridade:** dados não alterados
  - **Autenticidade/Autorização:** verificar identidade e permissões

#### Técnicas de Autenticação
| Método     | Descrição                                                        |
| ---------- | ---------------------------------------------------------------- |
| OAuth      | Autorização sem compartilhar credenciais (login Google/Facebook) |
| JWT Tokens | Tokens seguros para autenticação em requests subsequentes        |

#### Melhores Práticas
- Criptografia SSL/TLS (HTTPS)
- Validação rigorosa de dados de entrada
- Proteção DDoS, WAF, monitoramento contínuo

### Casos de Uso Práticos
| Setor      | Exemplo         | Aplicação                                  |
| ---------- | --------------- | ------------------------------------------ |
| Saúde      | Telemedicina    | Consultas remotas, prontuários eletrônicos |
| E-commerce | Recomendações   | Personalização baseada em comportamento    |
| Finanças   | PayPal/Stripe   | Pagamentos seguros online                  |
| Educação   | Plataformas EAD | Cursos interativos, colaboração            |
| Streaming  | Netflix/YouTube | Conteúdo sob demanda, recomendações        |
| Mobilidade | Uber/Lyft       | Rastreamento, cálculo de tarifas           |

# Aula 5: DNS (Domain Name System)

## DNS (Domain Name System) e Segurança

### O que é DNS?
- Sistema distribuído que traduz nomes de domínio amigáveis (ex: www.exemplo.com) em endereços IP numéricos.
- Facilita o acesso a recursos na internet sem memorizar números complexos.
- Nomes de domínio são hierárquicos: subdomínio, domínio de segundo nível, domínio de topo (TLD).

### Hierarquia e Estrutura DNS
- Domínio de topo (TLD): Ex: .com, .org, .gov.
- Subdomínios: extensões do domínio principal para organizar recursos.
- Estrutura em árvore facilita organização e resolução de nomes.

### Servidores DNS
- Servidores de Resolução (recursivos): iniciam e realizam consultas, armazenam cache.
- Servidores Autoritativos: mantêm os registros DNS para domínios específicos.
- Servidores Raiz: topo da hierarquia, direcionam para servidores TLD.

### Funcionamento da Resolução DNS
- Cliente consulta servidor recursivo.
- Recursivo checa cache ou consulta servidores raiz, TLD e autoritativos conforme hierarquia.
- Resposta retornada ao cliente com endereço IP associado ao domínio.
- Uso de cache DNS para acelerar consultas futuras e reduzir tráfego.

### Cache DNS
- Armazena respostas temporariamente para acelerar resoluções.
- Tempo de Vida (TTL) determina validade do cache.
- Benefícios: rapidez, eficiência de rede, redução de carga nos servidores.
- Riscos: envenenamento de cache, ataques Man-in-the-Middle, ataques de replay.

### Segurança em DNS

#### DNSSEC (DNS Security Extensions)
- Extensão para autenticar e garantir integridade dos dados DNS.
- Usa assinaturas digitais para verificar respostas DNS.
- Previne envenenamento de cache e ataques MITM.
- Objetivo: garantir a autenticidade das respostas DNS na cadeia de confiança.

#### DNS over HTTPS (DoH) e DNS over TLS (DoT)
- Protocolo que criptografa consultas DNS para aumentar privacidade.
- DoH usa HTTPS; DoT usa TLS para proteger consultas contra interceptação.
- Protege contra vigilância e monitoramento em redes públicas.
- Pode dificultar filtragem e monitoramento por parte de administradores.

#### Tipos de Registros DNS
- Registro A: mapeia nomes para endereços IPv4.
- Registro AAAA: mapeia nomes para endereços IPv6.
- Registro MX: define servidores de email para entrega de mensagens.
- Registro CNAME: alias que aponta para outro domínio.
- Registro TXT: texto para autenticação, SPF, DKIM, DMARC.
- Registro NS: define servidores autoritativos do domínio.
- Registro SOA: autoridade e configuração da zona do domínio.
- Registro SRV: aponta para servidores de serviços específicos (ex: VoIP).
- Registro ALIAS: apelidos para serviços em nuvem, facilitando manutenção.

### Configuração de Servidores DNS
- Ferramentas comuns: BIND, Microsoft DNS Server.
- Passos: instalação, configuração inicial, criação de zonas, definição de registros, encaminhamento para servidores externos, testes.
- Importância de segurança e monitoramento para evitar ataques e garantir desempenho.

### Zoneamento DNS
- Divisão do domínio em zonas lógicas para facilitar gerenciamento.
- Zonas diretas: nome → IP.
- Zonas reversas: IP → nome.
- Benefícios: organização, escalabilidade, delegação de responsabilidade.

### Resolução de Problemas Comuns
- Erros de configuração de registros ou zonas.
- Falha na resolução de nomes.
- Ataques de envenenamento de cache.
- Problemas de roteamento e conectividade.
- Ferramentas de diagnóstico: dig, nslookup, traceroute.
- Importância da documentação e backups para recuperação rápida.

# Aula 6: Arquitetura da Internet

## Arquitetura Geral da Internet
- **Natureza descentralizada:** rede de redes sem controle central único.
- **Componentes principais:**
  - ISPs (provedores de Internet)
  - Backbones (espinha dorsal)
  - IXPs (Pontos de Troca de Tráfego) 

## Backbones de Internet
- **Definição:** redes de alta capacidade que interconectam regiões geográficas globais.
- **Infraestrutura:** cabos de fibra óptica, roteadores de alto desempenho.

### Principais Backbones Globais
| Operadora             | Cobertura Principal              |
| --------------------- | -------------------------------- |
| Level 3/CenturyLink   | Global extenso                   |
| AT&T                  | América do Norte, Europa, Ásia   |
| NTT Communications    | Ásia, global                     |
| TATA Communications   | Global                           |
| Globenet              | América Latina                   |
| **Embratel (Brasil)** | Nacional                         |

### Pontos de Troca de Tráfego (IXPs)
- **Função:** redes conectam-se fisicamente para trocar tráfego localmente.
- **Benefícios:**
  - Reduz latência (tráfego não viaja longas distâncias)
  - Alivia carga dos backbones
  - Maior resiliência e redundância
  - Promove inovação e competição 

### Problemas nos Backbones e Soluções
| Problema              | Soluções                                                             |
| --------------------- | -------------------------------------------------------------------- |
| Congestionamento      | Upgrade infraestrutura, otimização roteamento                        |
| Falhas hardware       | Redundância (rotas/equipamentos alternativos)                        |
| Ataques cibernéticos  | Firewalls, IDS, análise de tráfego                                   |
| Otimização roteamento | Algoritmos BGP/OSPF, monitoramento constante  |

## Desafios de Segurança na Internet

### Tipos de Malware
| Tipo           | Característica                                              |
| -------------- | ----------------------------------------------------------- |
| **Vírus**      | Anexa-se a arquivos legítimos, replica-se                   |
| **Worms**      | Autônomo, propaga via rede                                  |
| **Trojans**    | Disfarça-se de software legítimo                            |
| **Spyware**    | Coleta dados sem consentimento                              |
| **Adware**     | Exibe anúncios indesejados                                  |
| **Ransomware** | Criptografa arquivos, exige resgate                         |

### Outras Ameaças
- **Phishing:** e-mails/sites falsos para roubar credenciais
- **DDoS:** sobrecarga de tráfego para derrubar serviços
- **Engenharia Social:** manipulação psicológica (pretexting, tailgating, quid pro quo)
- **BGP Hijacking:** sequestro de rotas
- **IoT inseguro:** dispositivos vulneráveis 

## Gerenciamento de Tráfego e QoS
- **QoS (Quality of Service):** prioriza tráfego crítico (voz > vídeo > dados).
- **Técnicas:**
  - Reserva de largura de banda
  - Gerenciamento de congestionamento
  - Redução de latência/jitter
  - Equilíbrio de carga
  - Roteamento inteligente 

## Transição IPv4 → IPv6
| Protocolo | Bits | Endereços              | Status                                         |
| --------- | ---- | ---------------------- | ---------------------------------------------- |
| **IPv4**  | 32   | ~4,3 bilhões           | Esgotado                                       |
| **IPv6**  | 128  | Praticamente ilimitado | Transição em andamento                         |

## Roteadores e Encaminhamento
- **Função:** conectam redes heterogêneas, decidem próximo salto.
- **Componentes:**
  - Interfaces múltiplas (Ethernet, Wi-Fi, fibra)
  - Tabelas de roteamento dinâmicas
  - Protocolos: OSPF, BGP, RIP, EIGRP
  - NAT, QoS, firewalls integrados 

### Processo de Decisão
1. Analisa cabeçalho (IP origem/destino, portas, TTL)
2. Consulta tabela de roteamento
3. Escolhe melhor rota (latência, custo, largura de banda)
4. Encaminha para próximo salto

# Aula 7: Redes de Computadores

## Classificação de Redes por Abrangência Geográfica
- **LAN (Local Area Network):** redes locais de alta velocidade e baixa latência em pequenos espaços (casa, escritório, campus).
- **WAN (Wide Area Network):** conectam LANs distantes, cidades ou países, usando infraestrutura especializada (linhas alugadas, VPNs, fibra óptica).
- **MAN (Metropolitan Area Network):** abrangem cidades ou regiões metropolitanas, conectando múltiplas LANs em média distância.
- **PAN (Personal Area Network):** conexão de curto alcance entre dispositivos pessoais (Bluetooth, NFC).

### Comparação entre LAN e WAN
| Aspecto           | LAN                       | WAN                             |
| ----------------- | ------------------------- | ------------------------------- |
| Escala Geográfica | Alguns metros a poucos km | Centenas a milhares de km       |
| Velocidade        | Alta                      | Variável, geralmente menor      |
| Latência          | Baixa                     | Maior devido a distância        |
| Aplicações        | Escritórios, residências  | Multinacionais, acessos remotos |

### Protocolos usados em WANs
- IPv4 e IPv6 (endereçamento)
- BGP (roteamento entre sistemas autônomos)
- MPLS (encaminhamento eficiente com rótulos)
- Frame Relay e ATM (legados)
- PPP e PPPoE (conexões ponto a ponto)
- VPNs com IPsec, SSL/TLS para segurança
- TCP e UDP para transporte [attached_file:file:17]

### Tecnologias e protocolos em MAN
- Metro Ethernet, ATM, SONET/SDH, RPR.
- MPLS e EoMPLS para roteamento eficiente e QoS.
- Alcance geográfico ideal para redes metropolitanas (dezenas de km).

### Tecnologias em PAN
- Bluetooth, NFC, Zigbee, Wireless USB, IrDA.
- Comunicação de curto alcance, focada em dispositivos pessoais.
- Comparação: PANs para comunicação próxima; LANs abrange mais dispositivos em espaço maior.

### Redes Celulares: 3G, 4G, 5G
- 3G: transmissão de voz/dados mais rápida, videochamadas.
- 4G (LTE): alta velocidade, streaming HD, jogos online.
- 5G: ultra rápidas, baixa latência, alta capacidade para IoT, slicing de rede.

### Dispositivos de Rede em LAN
- **Switches:** operam com endereços MAC, encaminham frames para destino específico.
- **Roteadores:** conectam redes, operam com IPs, podem incluir NAT e firewalls.
- **Hubs:** enviam dados para todas as portas, menos eficiente que switch.
- **Access Points:** estendem redes sem fio (Wi-Fi).
- **Firewalls:** controlam tráfego para segurança.
- **Servidores:** oferecem recursos compartilhados e atribuem IPs (DHCP).
- **Modems:** conectam LAN à internet convertendo sinais.

### Arquiteturas de LAN
- Ethernet (topologia estrela/barramento, CSMA/CD e CSMA/CA).
- Token Ring (topologia em anel com passagem de token).
- FDDI (anel duplo em fibra óptica, alta velocidade e redundância).
- ARCnet (topologia barramento, custo eficiente).
- WLAN (Wi-Fi, operação nas faixas 2.4 GHz e 5 GHz).
- Powerline LAN (uso da rede elétrica para comunicação).

### Tecnologias de interconexão em WAN
- Linhas alugadas (circuitos dedicados).
- VPNs para conexão segura sobre internet pública.
- MPLS para roteamento eficiente com QoS.
- SD-WAN utiliza software para otimização dinâmica.
- Redes privadas dedicadas para controle absoluto.

### Protocolos Wi-Fi e Segurança
- IEEE 802.11 (familia de padrões Wi-Fi, incluindo 802.11b/g/n/ac/ax).
- Protocolos de segurança: WPA, WPA2, WPA3 e 802.11i.
- Extensões para roaming e gerenciamento: 802.11r/k/v.
- Wi-Fi Direct para conexão direta entre dispositivos.
- Práticas recomendadas: uso de WPA2/WPA3, senhas fortes, SSID oculto, filtragem MAC, atualizações regulares, desativação de serviços inseguros, segmentação de rede e uso de VPN.


# Aula 8: Segurança de Redes

## Ameaças Comuns à Segurança de Redes
- Malware: vírus, worms, trojans, ransomware que causam danos ou roubam informações.
- Phishing: tentativas de enganar usuários para obter dados confidenciais.
- Ataques DoS/DDoS: sobrecarregam serviços para torná-los inacessíveis.
- Engenharia Social: manipulação psicológica para obter informações.
- Vulnerabilidades de software: falhas exploradas por invasores.
- Interceptação de dados: captura não autorizada durante transmissões.
- Roubo de identidade: obtenção ilegal de dados pessoais.
- Backdoors e exploits: meios para contornar autenticação.
- Injeção de código: SQL Injection, XSS para comprometer aplicações.
- Insider Threats: ameaças internas (funcionários ou contratados).

## Exploração de Vulnerabilidades
- Varredura automática e análise de código para encontrar falhas.
- Ataques zero-day e baseados em buffer overflow.
- Phishing pode entregar malware camuflado.
- Impactos incluem interrupção de serviços, acesso não autorizado, roubo e alteração de dados, propagação lateral de malware e prejuízos financeiros e reputacionais.

## Prevenção e Mitigação
- Atualizações regulares de software.
- Testes de penetração periódicos.
- Conscientização dos usuários sobre segurança.

## Firewalls
- Atuam como barreira entre redes internas e externas.
- Tipos: firewall de pacotes, stateful, proxy (aplicação) e NGFW (próxima geração).
- Funções: filtragem, NAT, proxy, detecção/prevenção de intrusão, VPN, logging/auditoria.
- Firewalls de pacotes: filtragem baseada em IPs, portas, protocolos (stateless).
- Firewalls stateful: mantêm estado das conexões para decisões contextuais.
- Firewalls de aplicação: inspeção profunda de pacotes, controle granular por aplicação.
- NGFWs: combinam múltiplas funções com prevenção avançada, análise de comportamento e integração com nuvem.

## Antivírus
- Detecta, previne e remove malware.
- Usa assinaturas, heurística comportamental e análise de código.
- Proteção em tempo real e varreduras programadas.
- Baixo impacto no desempenho e recursos adicionais (firewall, anti-phishing).

## Redes Privadas Virtuais (VPNs)
- Criam túnel criptografado para comunicação segura sobre redes públicas.
- Tipos: acesso remoto, site-to-site, L2VPN, L3VPN.
- Protocolos comuns: IPsec, SSL/TLS, PPTP/L2TP.
- Benefícios: segurança, acesso remoto seguro, conexão entre filiais, proteção em redes públicas, economia e escalabilidade.
- Considerações: escolha de protocolos, políticas de segurança, manutenção, conformidade regulatória.

# Aula 9: Segurança na Web

## Evolução HTTP → HTTPS
- **HTTP:** transmite dados em texto simples, vulnerável a interceptações.
- **HTTPS:** extensão segura do HTTP com criptografia SSL/TLS.
- **Pilares do HTTPS:**
  - Confidencialidade: dados criptografados
  - Autenticação: certificados digitais verificam servidor
  - Integridade: garante dados não alterados [attached_file:file:19]

## Vulnerabilidades do HTTP
| Vulnerabilidade              | Impacto                                            |
| ---------------------------- | -------------------------------------------------- |
| **Sniffing**                 | Interceptação e leitura de dados sensíveis         |
| **Man-in-the-Middle (MitM)** | Interceptação/alteração da comunicação             |
| **Falsificação de conteúdo** | Injeção de conteúdo malicioso                      |
| **Roubo de credenciais**     | Exposição de logins/senhas [attached_file:file:19] |
## Mecanismos HTTPS
- **Criptografia de dados:** SSL/TLS protege transmissão
- **Certificados digitais:** obrigatórios, emitidos por Autoridades Certificadoras (CAs)
- **Integridade:** códigos MAC verificam alterações
- **Proteção MitM:** criptografia impede leitura/modificação

## SSL/TLS
- **Criptografia híbrida:**
  - **Simétrica** (AES): eficiente para grandes volumes de dados
  - **Assimétrica** (RSA): autenticação e troca segura de chaves
- **Handshake SSL/TLS:**
  1. Cliente inicia conexão segura
  2. Servidor apresenta certificado
  3. Cliente autentica certificado
  4. Acordo de chave de sessão
  5. Comunicação criptografada [attached_file:file:19]

## Autoridades Certificadoras (CAs)
- **Processo de emissão:**
  1. Escolha da CA (Let's Encrypt, DigiCert, Symantec)
  2. Solicitação e geração de chaves
  3. Verificação de identidade do solicitante
  4. Emissão do certificado assinado
- **Instalação:** configuração em Apache/Nginx/IIS
- **Renovação:** automática (Certbot) ou manual antes da expiração

## Tipos de Certificados
| Tipo   | Validação            | Visualização                 | Uso                                   |
| ------ | -------------------- | ---------------------------- | ------------------------------------- |
| **EV** | Estendida (rigorosa) | Nome da organização na barra | Bancos, e-commerce                    |
| **OV** | Organização          | Nome da organização          | Empresas médias                       |
| **DV** | Apenas domínio       | Cadeado básico               | Sites simples                         |

## Indicadores de Segurança nos Navegadores
- **Ícone de cadeado:** conexão HTTPS criptografada
- **Barra verde:** certificado EV (alta confiança)
- **"Conexão Segura":** confirmação textual
- **Avisos:** certificados inválidos/expirados
- **Clique no cadeado:** detalhes do certificado (emissor, validade)

## Criptografia de Dados
- **Conceitos fundamentais:**
  - **Cifra:** algoritmo matemático (simétrica/assimétrica)
  - **Chave:** parâmetro para cifrar/decifrar
  - **Algoritmo:** sequência de passos criptográficos
- **Objetivos:**
  - Confidencialidade, integridade, autenticidade, proteção MitM, privacidade

## Criptografia Simétrica vs Assimétrica
| Aspecto          | Simétrica              | Assimétrica                                 |
| ---------------- | ---------------------- | ------------------------------------------- |
| **Chave**        | Única (compartilhada)  | Par (pública/privada)                       |
| **Eficiência**   | Alta (grandes volumes) | Baixa (computacional)                       |
| **Distribuição** | Desafio (segura)       | Fácil (pública aberta)                      |
| **Uso típico**   | Dados em trânsito      | Autenticação/chaves                         |

## Criptografia Ponta a Ponta
- **Definição:** apenas remetente/destinatário decifram
- **Casos de uso:** WhatsApp, transações financeiras, armazenamento em nuvem
- **Desafios:** gestão de chaves, performance, experiência do usuário

## Verificação de Certificados
- **Autenticação do servidor:** validação durante handshake
- **Cadeia de confiança:** CA raiz → certificado intermediário → servidor
- **Consequências da expiração:** interrupção de serviços, riscos de segurança, perda de confiança

# Aula 10: Tendências e Desafios nas Redes Modernas

## Internet das Coisas (IoT)
- **Definição:** objetos físicos conectados à internet com sensores para coleta/troca de dados.
- **Exemplos práticos:**
  | Dispositivo | Aplicação |
  |-------------|-----------|
  | Termostatos inteligentes | Controle automático de temperatura |
  | Smartwatches | Monitoramento biométrico |
  | Sensores agrícolas | Otimização de produção |
  | Veículos conectados | Segurança/eficiência |
  | Cidades inteligentes | Gestão de tráfego/resíduos |

### Desafios de Integração IoT
| Desafio                      | Soluções                                            |
| ---------------------------- | --------------------------------------------------- |
| **Endereços IP**             | IPv6 para escalabilidade                            |
| **Largura de banda**         | Otimização de infraestrutura                        |
| **Segurança**                | Autenticação, criptografia, monitoramento           |
| **Gerenciamento de energia** | Protocolos de baixo consumo                         |

### Protocolos IoT
- **MQTT:** mensagens leves para redes restritas
- **CoAP:** dispositivos com hardware limitado
- **HTTP/HTTPS:** integração com web
- **LoRaWAN:** longo alcance para áreas extensas 

## Redes Definidas por Software (SDN)
- **Conceito:** separa plano de controle (decisões) do plano de dados (transmissão).
- **Componentes:**

| Componente      | Função                               |
| --------------- | ------------------------------------ |
| Controlador SDN | Cérebro central (OpenFlow, APIs)     |
| Switches SDN    | Executam instruções do controlador   |
| APIs            | Comunicação controlador-dispositivos |
| OpenFlow        | Protocolo de controle de tráfego     |


### Benefícios SDN
- Adaptação dinâmica em tempo real
- Otimização de recursos (banda, roteamento)
- Suporte rápido a novos serviços
- **Casos de uso:** data centers, redes empresariais, provedores WAN 

## Web 3.0 e Blockchains
- **Descentralização:** elimina intermediários (bancos, plataformas)
- **Propriedade de dados:** controle total pelo usuário
- **Contratos inteligentes:** autoexecutáveis na blockchain
- **Interoperabilidade:** comunicação fluida entre plataformas

### Casos de Uso Blockchain (além criptomoedas)
| Aplicação              | Benefício                                      |
| ---------------------- | ---------------------------------------------- |
| Contratos inteligentes | Automação imobiliária/seguros                  |
| Gestão de identidade   | Controle pessoal de dados                      |
| Cadeia de suprimentos  | Transparência/rastreabilidade                  |
| Saúde                  | Registros médicos seguros                      |
| Votação eletrônica     | Transparência imutável                         |

## Machine Learning e IA na Segurança
- **Princípios ML:** treinamento por experiência, algoritmos adaptativos.
- **Tipos:** supervisionado, não supervisionado, reforço.
- **Aplicações de segurança:**
  - Análise comportamental de tráfego
  - Detecção de malware polimórfico
  - Prevenção de ameaças avançadas (APTs)

## Autenticação Multifatorial (MFA) e Biometria
- **MFA:** senha + código SMS/app/token físico
- **Biometria:** impressões digitais, facial, íris
- **Biometria comportamental:** análise de digitação/padrões

## CDNs e Segurança (Cloudflare)
- **Distribuição global:** reduz latência, mitiga DDoS
- **WAF:** proteção contra SQL injection/XSS
- **SSL/TLS termination:** criptografia sem sobrecarga
- **DNS Anycast:** velocidade/resistência a ataques
- **Zero Trust:** autenticação antes do acesso [attached_file:file:20]

## Abordagem On-Premise vs Nuvem
### On-Premise
| Vantagem                 | Desvantagem                                     |
| ------------------------ | ----------------------------------------------- |
| Controle total           | Alto custo inicial                              |
| Conformidade regulatória | Manutenção manual                               |
| Baixa latência           | Escalabilidade limitada                         |

### Nuvem
| Vantagem                 | Desvantagem                                               |
| ------------------------ | --------------------------------------------------------- |
| Escalabilidade           | Dependência do provedor                                   |
| Atualizações automáticas | Menos controle                                            |
| Baixo custo inicial      | Possíveis questões de privacidade                         |

### Principais Provedores Cloud
- **AWS, Azure, Google Cloud, IBM Cloud, Alibaba, Oracle, DigitalOcean, VMware, Red Hat OpenShift, Salesforce**

## Ataques Cibernéticos Sofisticados
- Engenharia social avançada (phishing personalizado)
- APTs (Advanced Persistent Threats)
- Ransomware com exfiltração de dados
- Zero-day exploits
- Uso de IA/ML pelos atacantes

