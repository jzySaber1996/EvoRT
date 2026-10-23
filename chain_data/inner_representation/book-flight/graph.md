graph TD
    Z[用户查询：输入个人用户名、手机号、邮箱等信息] --> A[FlightInformationRetrieval]
    A[FlightInformationRetrieval] --> B[UserIDValidation]
    A[FlightInformationRetrieval] --> H[UserPhonenumberValidation]
    B --> C{UserValidation返回值}
    H --> C{UserValidation返回值}
    C -->|True| E[BookTargetFlight]
    C -->|True| K[BookCtripFlight]
    C -->|False| Z
    E --> I{BookFlight返回值}
    K --> I
    I --> |True| J[SendUserInformation]
    I --> |False| E
    I --> |False| K
    J --> M[完成订票任务]